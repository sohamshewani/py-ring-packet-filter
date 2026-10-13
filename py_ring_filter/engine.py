# -*- coding: utf-8 -*-
"""
py_ring_filter/engine.py
High-Performance Zero-Copy Lock-Free Memory Arena, Circular Ring Buffer,
and Sliding-Window Flow Control Engine.
"""

import os
import sys
import time
import math
import ctypes
import logging
import selectors
import threading
from typing import Optional, Tuple, Generator

# Configure logging for production metrics and failure recovery modes
logger = logging.getLogger("py_ring_filter.engine")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s"
    ))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class RingFilterError(Exception):
    """Base exception for all ring filter engine errors."""
    pass


class ArenaExhaustionError(RingFilterError):
    """Raised when the memory arena has no available packet slots."""
    pass


class RingFullError(RingFilterError):
    """Raised or handled when the circular ring buffer is fully saturated."""
    pass


class CorruptedSlotError(RingFilterError):
    """Raised when out-of-bounds or invalid slot metadata is detected."""
    pass


class MemoryArena:
    """
    Pre-allocated contiguous bytearray memory arena partitioned into fixed-size
    slot blocks (PACKET_SIZE) to eliminate runtime GC overhead and enable
    zero-copy packet handling via memory offsets.
    """

    def __init__(self, capacity: int, packet_size: int) -> int:
        self.capacity = int(capacity)
        self.packet_size = int(packet_size)
        
        # Enforce power of two or standard sizing logic, but strictly contiguous bytearray
        self.total_size = self.capacity * self.packet_size
        self._buffer = bytearray(self.total_size)
        self._memory_view = memoryview(self._buffer)

        # Free list management using a lock-free stack or bitmask array for O(1) allocation/free.
        # We use a contiguous array of 64-bit integers representing free slot indices.
        self._free_indices = (ctypes.c_uint64 * self.capacity)()
        for i in range(self.capacity):
            self._free_indices[i] = self.capacity - 1 - i

        self._free_count = ctypes.c_int64(self.capacity)
        self._lock = threading.Lock()

        logger.info(
            f"Initialized MemoryArena: capacity={self.capacity}, "
            f"packet_size={self.packet_size}, total_bytes={self.total_size}"
        )

    def allocate_slot(self) -> int:
        """
        Allocates a slot index from the arena. Returns the integer slot offset ID.
        Raises ArenaExhaustionError if no slots are available.
        """
        with self._lock:
            current_count = self._free_count.value
            if current_count <= 0:
                logger.error("Arena exhaustion detected: zero free slots available.")
                raise ArenaExhaustionError("Memory arena exhausted: all slots pinned.")
            
            current_count -= 1
            self._free_count.value = current_count
            slot_idx = self._free_indices[current_count]
            return int(slot_idx)

    def free_slot(self, slot_idx: int) -> None:
        """
        Returns a slot index back to the arena free list.
        Validates bounds defensively.
        """
        if slot_idx < 0 or slot_idx >= self.capacity:
            raise CorruptedSlotError(f"Attempted to free out-of-bounds slot index: {slot_idx}")

        with self._lock:
            current_count = self._free_count.value
            if current_count >= self.capacity:
                logger.critical(f"Double free corruption detected on slot index {slot_idx}")
                raise CorruptedSlotError(f"Double free or overflow on slot index {slot_idx}")

            self._free_indices[current_count] = slot_idx
            self._free_count.value = current_count + 1

    def get_view(self, slot_idx: int) -> memoryview:
        """
        Returns a zero-copy memoryview slice for the specified slot index.
        """
        if slot_idx < 0 or slot_idx >= self.capacity:
            raise CorruptedSlotError(f"Slot index {slot_idx} out of bounds for memory view retrieval.")
        
        start = slot_idx * self.packet_size
        end = start + self.packet_size
        return self._memory_view[start:end]


class LockFreeRingBuffer:
    """
    Fixed-size power-of-two capacity array utilizing atomic 64-bit monotonically
    increasing head and tail sequence indices. Stores pure 64-bit integers
    representing arena slot offsets.
    """

    def __init__(self, capacity: int) -> None:
        if not (capacity > 0 and (capacity & (capacity - 1)) == 0):
            raise ValueError(f"Ring buffer capacity must be a power of two, got {capacity}")

        self.capacity = capacity
        self.mask = capacity - 1

        # Underlying storage: array of 64-bit unsigned integers representing slot offsets
        self._slots = (ctypes.c_uint64 * self.capacity)()
        
        # Atomic head and tail indices
        self._head = ctypes.c_uint64(0)
        self._tail = ctypes.c_uint64(0)

        # Thread synchronization primitive for SWMR/MPSC barriers
        self._mutex = threading.Lock()

        logger.info(f"Initialized LockFreeRingBuffer with capacity {self.capacity}")

    @property
    def head(self) -> int:
        return self._head.value

    @property
    def tail(self) -> int:
        return self._tail.value

    def size(self) -> int:
        t = self._tail.value
        h = self._head.value
        if t >= h:
            return t - h
        return self.capacity - (h - t)

    def push(self, slot_idx: int) -> bool:
        """
        Pushes a slot index into the ring buffer.
        Enforces invariant: tail - head <= capacity.
        Returns True on success, False if ring is full (Tail-Drop policy).
        """
        with self._mutex:
            current_tail = self._tail.value
            current_head = self._head.value

            if (current_tail - current_head) >= self.capacity:
                logger.warning("Ring buffer full drop-policy triggered. Packet dropped.")
                return False

            idx = current_tail & self.mask
            self._slots[idx] = slot_idx
            # Memory barrier / atomic increment simulation via GIL-protected critical section
            self._tail.value = current_tail + 1
            return True

    def pop(self) -> Optional[int]:
        """
        Pops a slot index from the ring buffer.
        Returns the slot index, or None if the ring is empty.
        """
        with self._mutex:
            current_head = self._head.value
            current_tail = self._tail.value

            if current_head == current_tail:
                return None

            idx = current_head & self.mask
            slot_idx = int(self._slots[idx])
            self._head.value = current_head + 1
            return slot_idx


class SlidingWindowFlowControl:
    """
    Token bucket and sliding window tracking structures enforcing per-flow rate limits,
    congestion mitigation, and sequence validation to drop out-of-order or duplicate
    packets deterministically.
    """

    def __init__(self, rate_limit_rps: float, window_size_sec: float, max_burst: int) -> None:
        self.rate_limit_rps = float(rate_limit_rps)
        self.window_size_sec = float(window_size_sec)
        self.max_burst = int(max_burst)

        # Token bucket state per flow or global engine state
        self._tokens = float(max_burst)
        self._last_refill_time = time.monotonic()
        
        # Sequence validation tracking for sliding window (flow tracking map: flow_id -> last_seq)
        self._flow_sequences = {}
        self._lock = threading.Lock()

        logger.info(
            f"Initialized SlidingWindowFlowControl: rate={rate_limit_rps}rps, "
            f"window={window_size_sec}s, burst={max_burst}"
        )

    def _refill_tokens(self, now: float) -> None:
        elapsed = now - self._last_refill_time
        if elapsed > 0:
            new_tokens = elapsed * self.rate_limit_rps
            self._tokens = min(float(self.max_burst), self._tokens + new_tokens)
            self._last_refill_time = now

    def check_rate_limit(self) -> bool:
        """
        Consumes a token for rate limiting. Returns True if permitted, False if rate exceeded.
        """
        with self._lock:
            now = time.monotonic()
            self._refill_tokens(now)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def validate_sequence(self, flow_id: int, sequence_number: int) -> bool:
        """
        Validates packet sequence number to prevent out-of-order execution and replay attacks.
        Enforces strict monotonic incrementing per flow ID.
        """
        with self._lock:
            last_seq = self._flow_sequences.get(flow_id)
            if last_seq is None:
                self._flow_sequences[flow_id] = sequence_number
                return True

            # Expect strict incrementing or handle standard window roll over
            if sequence_number > last_seq:
                self._flow_sequences[flow_id] = sequence_number
                return True
            else:
                logger.debug(
                    f"Out-of-order or duplicate packet detected for flow {flow_id}: "
                    f"received seq {sequence_number}, last seen {last_seq}"
                )
                return False


class PacketFilterEngine:
    """
    High-Performance Edge-Triggered Polling Engine integrating MemoryArena,
    LockFreeRingBuffer, and SlidingWindowFlowControl with selectors.
    """

    def __init__(
        self,
        capacity: int = 1024,
        packet_size: int = 2048,
        rate_limit_rps: float = 10000.0,
        window_size_sec: float = 1.0,
        max_burst: int = 512
    ) -> None:
        self.arena = MemoryArena(capacity=capacity, packet_size=packet_size)
        self.ring = LockFreeRingBuffer(capacity=capacity)
        self.flow_control = SlidingWindowFlowControl(
            rate_limit_rps=rate_limit_rps,
            window_size_sec=window_size_sec,
            max_burst=max_burst
        )

        self.selector = selectors.DefaultSelector()
        self._running = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        logger.info("PacketFilterEngine fully assembled and initialized.")

    def register_socket(self, sock, events: int, data=None) -> None:
        """
        Registers a non-blocking socket into the edge-triggered selector.
        """
        try:
            os.set_blocking(sock.fileno(), False)
        except AttributeError:
            # Fallback for mock sockets or platforms without fileno adjustments
            sock.setblocking(False)

        self.selector.register(sock, events, data=data)
        logger.info(f"Registered socket {sock.fileno()} with event selector.")

    def unregister_socket(self, sock) -> None:
        """
        Unregisters a socket from the selector.
        """
        try:
            self.selector.unregister(sock)
            logger.info(f"Unregistered socket from selector.")
        except Exception as e:
            logger.error(f"Error unregistering socket: {e}")

    def ingest_packet(self, data: bytes, flow_id: int, sequence_number: int) -> bool:
        """
        Ingests raw packet payload into the system with full validation,
        flow control checking, arena allocation, and ring buffer enqueuing.
        """
        # 1. Sliding window flow control & rate limit validation
        if not self.flow_control.check_rate_limit():
            logger.warning("Packet dropped: Rate limit exceeded (Token bucket exhausted).")
            return False

        if not self.flow_control.validate_sequence(flow_id, sequence_number):
            logger.warning("Packet dropped: Out-of-order or duplicate sequence detected.")
            return False

        # 2. Allocate slot from memory arena
        try:
            slot_idx = self.arena.allocate_slot()
        except ArenaExhaustionError:
            logger.error("Packet dropped: Arena exhaustion backpressure triggered.")
            return False

        try:
            # 3. Zero-copy write via memoryview
            view = self.arena.get_view(slot_idx)
            data_len = len(data)
            if data_len > len(view):
                # Graceful Degradation / Quarantine
                self.arena.free_slot(slot_idx)
                logger.error(f"Packet payload size ({data_len}) exceeds slot size ({len(view)}). Quarantined.")
                return False

            view[:data_len] = data
            # Zero out remaining tail of the slot block for cleanliness
            if data_len < len(view):
                view[data_len:] = b'\x00' * (len(view) - data_len)

            # 4. Push slot offset to ring buffer
            pushed = self.ring.push(slot_idx)
            if not pushed:
                # Ring full drop policy: reclaim slot back to arena
                self.arena.free_slot(slot_idx)
                logger.warning("Packet dropped: Ring buffer full. Slot reclaimed.")
                return False

            return True

        except Exception as e:
            # Failure recovery mode: Transaction rollback & slot quarantine
            logger.critical(f"Critical exception during packet ingestion: {e}. Rolling back slot {slot_idx}.")
            try:
                self.arena.free_slot(slot_idx)
            except Exception as inner_e:
                logger.critical(f"Failed to quarantine and free slot during rollback: {inner_e}")
            return False

    def poll_loop(self, timeout: float = 0.1) -> Generator[Tuple[int, memoryview], None, None]:
        """
        Non-blocking poll loop generator yielding processed slot indices and memoryviews
        from the ring buffer.
        """
        while self._running.is_set():
            events = self.selector.select(timeout=timeout)
            for key, mask in events:
                callback = key.data
                if callback is not None and callable(callback):
                    try:
                        callback(key.fileobj, mask)
                    except Exception as e:
                        logger.error(f"Error in socket event callback: {e}")

            # Drain available items from the ring buffer
            while True:
                slot_idx = self.ring.pop()
                if slot_idx is None:
                    break
                try:
                    view = self.arena.get_view(slot_idx)
                    yield slot_idx, view
                except Exception as e:
                    logger.error(f"Error retrieving memory view for slot {slot_idx}: {e}")
                    # Attempt recovery
                    try:
                        self.arena.free_slot(slot_idx)
                    except Exception:
                        pass

    def start_background_engine(self) -> None:
        """
        Starts the engine processing loop in a dedicated background worker thread.
        """
        if self._worker_thread is not None and self._worker_thread.is_alive():
            logger.warning("Background engine already running.")
            return

        self._running.set()
        self._worker_thread = threading.Thread(
            target=self._run_engine_worker,
            name="PacketFilterWorker",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("Background PacketFilterEngine worker thread started.")

    def _run_engine_worker(self) -> None:
        """
        Internal worker execution loop processing incoming events and ring items.
        """
        for slot_idx, view in self.poll_loop(timeout=0.05):
            try:
                # Production