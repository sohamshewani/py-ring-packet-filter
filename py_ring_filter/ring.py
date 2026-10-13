# -*- coding: utf-8 -*-
"""
py_ring_filter/ring.py

Production-grade implementation of a zero-copy memory arena, lock-free circular
ring buffer, and sliding-window flow control engine in Python.
Designed for high-throughput, low-latency packet filtering architectures.
"""

import os
import sys
import time
import ctypes
import logging
import threading
import selectors
from typing import Optional, Tuple, Generator

# Configure production logging
logger = logging.getLogger("py_ring_filter.ring")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# ============================================================================
# EXCEPTION HIERARCHY
# ============================================================================

class RingFilterError(Exception):
    """Base exception for all py_ring_filter operational faults."""
    pass

class ArenaExhaustionError(RingFilterError):
    """Raised when the memory arena has no available packet slots."""
    pass

class RingFullError(RingFilterError):
    """Raised when the circular ring buffer has reached max capacity (drop policy)."""
    pass

class SequenceViolationError(RingFilterError):
    """Raised when out-of-order, duplicate, or invalid sequence indices are detected."""
    pass

class QuarantineError(RingFilterError):
    """Raised when a memory slot is corrupted and quarantined."""
    pass


# ============================================================================
# ATOMIC PRIMITIVES & MEMORY BARRIERS
# ============================================================================

class AtomicCounter64:
    """
    Thread-safe 64-bit monotonically increasing counter utilizing threading.Lock
    backed memory barriers to ensure strict sequential consistency across
    multi-producer/multi-consumer execution contexts without ABA hazards.
    """
    __slots__ = ('_value', '_lock')

    def __init__(self, initial: int = 0) -> None:
        self._value = int(initial)
        self._lock = threading.Lock()

    def get(self) -> int:
        with self._lock:
            return self._value

    def increment_and_get(self) -> int:
        with self._lock:
            self._value += 1
            return self._value

    def set(self, value: int) -> None:
        with self._lock:
            self._value = int(value)

    def compare_and_swap(self, expected: int, desired: int) -> bool:
        with self._lock:
            if self._value == expected:
                self._value = desired
                return True
            return False


# ============================================================================
# 1. MEMORY ARENA & 3. MEMORY LAYOUT
# ============================================================================

class MemoryArena:
    """
    Pre-allocated contiguous bytearray partitioned into fixed-size slot blocks
    (`packet_size`). Eliminates runtime garbage collection overhead and enables
    zero-copy packet handling via memory offsets and memoryview slices.
    """
    __slots__ = ('_capacity', '_packet_size', '_arena', '_free_list', '_pinned_slots', '_lock')

    def __init__(self, capacity: int, packet_size: int) -> None:
        if capacity <= 0 or (capacity & (capacity - 1)) != 0:
            raise ValueError("Arena capacity must be a positive power of two.")
        if packet_size <= 0:
            raise ValueError("Packet size must be greater than zero.")

        self._capacity = capacity
        self._packet_size = packet_size
        
        # Pre-allocate contiguous physical memory block
        total_size = capacity * packet_size
        try:
            self._arena = bytearray(total_size)
        except MemoryError as exc:
            logger.critical("Failed to allocate contiguous memory arena of size %d bytes", total_size)
            raise ArenaExhaustionError("System out of memory for arena allocation.") from exc

        # Free list tracking available slot indices (LIFO stack for cache locality)
        self._free_list = list(range(capacity - 1, -1, -1))
        self._pinned_slots = set()
        self._lock = threading.Lock()

        logger.info("MemoryArena initialized: capacity=%d, packet_size=%d, total_bytes=%d",
                    capacity, packet_size, total_size)

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def packet_size(self) -> int:
        return self._packet_size

    def allocate_slot(self) -> int:
        """
        Allocates a slot index from the arena free list.
        Returns the integer slot index offset.
        Raises ArenaExhaustionError if all slots are pinned.
        """
        with self._lock:
            if not self._free_list:
                logger.warning("Arena exhaustion guard triggered: 0 slots available.")
                raise ArenaExhaustionError("Memory arena exhausted. All slots pinned.")
            slot_idx = self._free_list.pop()
            self._pinned_slots.add(slot_idx)
            return slot_idx

    def release_slot(self, slot_idx: int) -> None:
        """
        Reclaims a slot index, returning it to the free list after consumer acknowledgment.
        """
        if slot_idx < 0 or slot_idx >= self._capacity:
            raise IndexError(f"Slot index {slot_idx} out of bounds for capacity {self._capacity}")

        with self._lock:
            if slot_idx not in self._pinned_slots:
                logger.error("Attempted to release unpinned or already free slot: %d", slot_idx)
                raise QuarantineError(f"Double-free or corruption attempt on slot {slot_idx}")
            
            self._pinned_slots.remove(slot_idx)
            # Zero out slot payload memory for security and clean state reuse
            start = slot_idx * self._packet_size
            end = start + self._packet_size
            self._arena[start:end] = b'\x00' * self._packet_size
            self._free_list.append(slot_idx)

    def get_buffer_view(self, slot_idx: int) -> memoryview:
        """
        Returns a zero-copy memoryview slice pointing directly to the arena block.
        """
        if slot_idx < 0 or slot_idx >= self._capacity:
            raise IndexError(f"Slot index {slot_idx} out of bounds.")
        start = slot_idx * self._packet_size
        end = start + self._packet_size
        return memoryview(self._arena)[start:end]


# ============================================================================
# 2. LOCK-FREE CIRCULAR RING BUFFER & 4. INVARIANTS
# ============================================================================

class CircularRingBuffer:
    """
    Fixed-size power-of-two capacity array utilizing atomic 64-bit monotonically
    increasing head and tail sequence indices. Stores pure 64-bit integers
    representing arena slot offsets.
    """
    __slots__ = ('_capacity', '_mask', '_buffer', '_head', '_tail', '_drop_counter')

    def __init__(self, capacity: int) -> None:
        if capacity <= 0 or (capacity & (capacity - 1)) != 0:
            raise ValueError("Ring buffer capacity must be a positive power of two.")
        
        self._capacity = capacity
        self._mask = capacity - 1
        # Backing array stores arena slot indices (ints)
        self._buffer = [-1] * capacity
        self._head = AtomicCounter64(0)
        self._tail = AtomicCounter64(0)
        self._drop_counter = AtomicCounter64(0)

        logger.info("CircularRingBuffer initialized: capacity=%d", capacity)

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def drop_count(self) -> int:
        return self._drop_counter.get()

    def enqueue(self, slot_idx: int) -> bool:
        """
        Attempts to push a slot index into the ring buffer.
        Enforces invariant: `tail - head <= capacity`.
        Implements Ring Full Drop-Policy.
        """
        while True:
            head_val = self._head.get()
            tail_val = self._tail.get()

            # Enforce Invariant: tail - head <= capacity
            if (tail_val - head_val) >= self._capacity:
                self._drop_counter.increment_and_get()
                logger.debug("Ring full drop-policy triggered. Tail: %d, Head: %d", tail_val, head_val)
                raise RingFullError("Ring buffer capacity reached. Packet dropped.")

            # Attempt atomic advance of tail pointer
            if self._tail.compare_and_swap(tail_val, tail_val + 1):
                index = tail_val & self._mask
                self._buffer[index] = slot_idx
                return True

    def dequeue(self) -> Optional[int]:
        """
        Attempts to pop a slot index from the ring buffer.
        Returns the slot index, or None if the buffer is empty.
        """
        while True:
            head_val = self._head.get()
            tail_val = self._tail.get()

            if head_val >= tail_val:
                # Buffer is empty
                return None

            index = head_val & self._mask
            slot_idx = self._buffer[index]

            # Attempt atomic advance of head pointer
            if self._head.compare_and_swap(head_val, head_val + 1):
                self._buffer[index] = -1  # Clear reference
                return slot_idx


# ============================================================================
# 3. SLIDING-WINDOW FLOW CONTROL & PACKET VALIDATION
# ============================================================================

class SlidingWindowFlowController:
    """
    Token bucket and sliding window tracking structures enforcing per-flow
    rate limits, congestion mitigation, and sequence validation to drop
    out-of-order or duplicate packets deterministically.
    """
    __slots__ = ('_window_size', '_rate_limit', '_tokens', '_last_refill', 
                 '_expected_seq', '_seen_window', '_lock')

    def __init__(self, window_size: int, rate_limit_pps: float) -> None:
        if window_size <= 0:
            raise ValueError("Window size must be greater than zero.")
        if rate_limit_pps <= 0.0:
            raise ValueError("Rate limit must be greater than zero.")

        self._window_size = window_size
        self._rate_limit = rate_limit_pps
        self._tokens = float(rate_limit_pps)
        self._last_refill = time.monotonic()
        self._expected_seq = 0
        self._seen_window = set()
        self._lock = threading.Lock()

        logger.info("SlidingWindowFlowController initialized: window_size=%d, rate_limit=%.2f pps",
                    window_size, rate_limit_pps)

    def _refill_tokens(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed > 0.0:
            new_tokens = elapsed * self._rate_limit
            self._tokens = min(self._rate_limit, self._tokens + new_tokens)
            self._last_refill = now

    def validate_and_rate_limit(self, sequence_id: int) -> bool:
        """
        Validates packet sequence ID against sliding window and checks token bucket.
        Returns True if packet is accepted, False if rate-limited or out-of-order.
        """
        with self._lock:
            self._refill_tokens()

            # 1. Token Bucket Rate Limit Check
            if self._tokens < 1.0:
                logger.debug("Token bucket exhausted. Rate limiting packet seq=%d", sequence_id)
                return False

            # 2. Sliding Window Sequence Validation
            if sequence_id < 0:
                raise SequenceViolationError(f"Negative sequence ID encountered: {sequence_id}")

            # Check for duplicates or severe out-of-order bounds
            if sequence_id in self._seen_window:
                logger.debug("Duplicate packet detected and dropped. seq=%d", sequence_id)
                return False

            if sequence_id < self._expected_seq - self._window_size:
                logger.debug("Packet too old (outside sliding window). seq=%d, expected>=%d",
                             sequence_id, self._expected_seq - self._window_size)
                return False

            # Consume token
            self._tokens -= 1.0

            # Advance window tracking
            self._seen_window.add(sequence_id)
            if sequence_id >= self._expected_seq:
                self._expected_seq = sequence_id + 1

            # Purge stale sequence IDs outside current sliding window
            lower_bound = self._expected_seq - self._window_size
            # Mutate set safely while filtering
            self._seen_window = {s for s in self._seen_window if s >= lower_bound}

            return True


# ============================================================================
# 5. NON-BLOCKING POLL LOOPS & PRODUCTION ENGINE ORCHESTRATION
# ============================================================================

class RingPacketFilterEngine:
    """
    High-throughput non-blocking poll loop and packet filtering orchestration engine.
    Integrates MemoryArena, CircularRingBuffer, and SlidingWindowFlowController
    with selectors.DefaultSelector for edge-triggered socket event processing.
    """
    __slots__ = ('_arena', '_ring', '_flow_controller', '_selector', '_running', '_poll_thread')

    def __init__(self, arena_capacity: int = 4096, packet_size: int = 1536,
                 window_size: int = 1024, rate_limit_pps: float = 10000.0) -> None:
        self._arena = MemoryArena(capacity=arena_capacity, packet_size=packet_size)
        self._ring = CircularRingBuffer(capacity=arena_capacity)
        self._flow_controller = SlidingWindowFlowController(window_size=window_size, rate_limit_pps=rate_limit_pps)
        self._selector = selectors.DefaultSelector()
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None

        logger.info("RingPacketFilterEngine successfully constructed.")

    def register_socket_source(self, sock, callback) -> None:
        """
        Registers a non-blocking socket descriptor with the edge-triggered selector.
        """
        os.set_blocking(sock.fileno(), False)
        self._selector.register(sock, selectors.EVENT_READ, data=callback)
        logger.info("Registered file descriptor %d into non-blocking poll loop.", sock.fileno())

    def unregister_socket_source(self, sock) -> None:
        self._selector.unregister(sock)
        logger.info("Unregistered file descriptor %d from poll loop.", sock.fileno())

    def ingest_packet(self, raw_data: bytes, sequence_id: int) -> bool:
        """
        Zero-copy ingestion pipeline:
        1. Validates flow rate and sequence sliding window.
        2. Allocates arena slot.
        3. Copies raw data directly into the arena memoryview slice.
        4. Enqueues slot index into the lock-free ring buffer.
        """
        # Flow Control Validation
        if not self._flow_controller.validate_and_rate_limit(sequence_id):
            return False

        # Arena Allocation with Exhaustion Guard
        try:
            slot_idx = self._arena.allocate_slot()
        except ArenaExhaustionError:
            logger.error("Arena exhaustion encountered during ingestion. Backpressure applied.")
            return False

        # Zero-Copy Write into Arena Memoryview
        try:
            buf_view = self._arena.get_buffer_view(slot_idx)
            data_len = len(raw_data)
            if data_len > len(buf_view):
                self._arena.release_slot(slot_idx)
                raise ValueError(f"Packet payload size {data_len} exceeds slot capacity {len(buf_view)}")
            
            buf_view[:data_len] = raw_data
            # Zero out remainder of the slot block
            if data_len < len(buf_view):
                buf_view[data_len:] = b'\x00' * (len(buf_view) - data_len)

        except Exception as exc:
            logger.critical("Transaction rollback: failure writing to arena slot %d: %s", slot_idx, exc)
            self._arena.release_slot(slot_idx)
            raise QuarantineError(f"Quarant