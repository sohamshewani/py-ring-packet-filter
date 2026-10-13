import os
import sys
import ctypes
import selectors
import threading
import time
import socket
from typing import Optional, Tuple, Generator, List

# ============================================================================
# EXCEPTION HIERARCHY
# ============================================================================

class RingFilterError(Exception):
    """Base exception class for all py_ring_filter errors."""
    pass

class ArenaExhaustionError(RingFilterError):
    """Raised when the memory arena runs out of available packet slots."""
    pass

class RingFullError(RingFilterError):
    """Raised when the circular ring buffer is full and drop policy is strict."""
    pass

class OutOfBoundsError(RingFilterError):
    """Raised when an invalid slot offset or index is accessed."""
    pass

class CorruptionError(RingFilterError):
    """Raised when packet headers or ring quadrants are found to be corrupted."""
    pass


# ============================================================================
# ATOMIC COUNTERS & CONCURRENCY PRIMITIVES
# ============================================================================

class AtomicCounter64:
    """Thread-safe 64-bit monotonically increasing atomic counter using threading locks."""
    
    def __init__(self, initial_value: int = 0) -> None:
        self._value = int(initial_value)
        self._lock = threading.Lock()

    def get(self) -> int:
        with self._lock:
            return self._value

    def increment(self, amount: int = 1) -> int:
        with self._lock:
            self._value += amount
            return self._value

    def compare_and_swap(self, expected: int, desired: int) -> bool:
        with self._lock:
            if self._value == expected:
                self._value = desired
                return True
            return False

    def set(self, value: int) -> None:
        with self._lock:
            self._value = value


# ============================================================================
# MEMORY ARENA & ZERO-COPY SLOT ALLOCATOR
# ============================================================================

class MemoryArena:
    """
    Pre-allocated contiguous bytearray partitioned into fixed-size slot blocks.
    Eliminates runtime GC overhead and enables zero-copy packet handling via offsets.
    """

    def __init__(self, capacity: int, packet_size: int) -> None:
        self.capacity = int(capacity)
        self.packet_size = int(packet_size)
        self.total_size = self.capacity * self.packet_size
        
        # Contiguous block allocation layout
        self._buffer = bytearray(self.total_size)
        self._memory_view = memoryview(self._buffer)
        
        # Free list tracking using a bitset / stack of free slot indices
        self._free_indices = list(range(self.capacity - 1, -1, -1))
        self._allocated_flags = [False] * self.capacity
        self._lock = threading.Lock()
        
        # Metrics
        self.alloc_failures = AtomicCounter64(0)
        self.quarantined_slots = AtomicCounter64(0)

    def allocate(self) -> int:
        """Allocates a slot index. Returns the absolute byte offset in the arena."""
        with self._lock:
            if not self._free_indices:
                self.alloc_failures.increment(1)
                raise ArenaExhaustionError("Memory arena exhausted: all slots pinned.")
            
            slot_idx = self._free_indices.pop()
            if self._allocated_flags[slot_idx]:
                self.alloc_failures.increment(1)
                raise CorruptionError(f"Arena corruption: slot {slot_idx} was already allocated.")
            
            self._allocated_flags[slot_idx] = True
            return slot_idx * self.packet_size

    def release(self, slot_offset: int) -> None:
        """Reclaims a slot back to the free list given its byte offset."""
        if slot_offset < 0 or slot_offset >= self.total_size or slot_offset % self.packet_size != 0:
            self.quarantined_slots.increment(1)
            raise OutOfBoundsError(f"Invalid slot offset for release: {slot_offset}")
        
        slot_idx = slot_offset // self.packet_size
        
        with self._lock:
            if not self._allocated_flags[slot_idx]:
                self.quarantined_slots.increment(1)
                raise CorruptionError(f"Double free or invalid release of slot index {slot_idx}.")
            
            # Zero out the slot memory for security and hygiene
            slot_view = self._memory_view[slot_offset : slot_offset + self.packet_size]
            slot_view[:] = b'\x00' * self.packet_size
            
            self._allocated_flags[slot_idx] = False
            self._free_indices.append(slot_idx)

    def get_view(self, slot_offset: int, size: Optional[int] = None) -> memoryview:
        """Returns a zero-copy memoryview slice for a given slot offset."""
        if slot_offset < 0 or slot_offset >= self.total_size or slot_offset % self.packet_size != 0:
            raise OutOfBoundsError(f"Attempted to access out-of-bounds offset: {slot_offset}")
        
        actual_size = size if size is not None else self.packet_size
        if actual_size > self.packet_size:
            raise OutOfBoundsError(f"Requested size {actual_size} exceeds slot packet size {self.packet_size}")
        
        return self._memory_view[slot_offset : slot_offset + actual_size]

    def quarantine_quadrant(self, start_slot_idx: int, count: int) -> None:
        """Quarantines a quadrant of slots during recovery mode."""
        with self._lock:
            for i in range(count):
                idx = (start_slot_idx + i) % self.capacity
                self._allocated_flags[idx] = False
                offset = idx * self.packet_size
                self._memory_view[offset : offset + self.packet_size] = b'\x00' * self.packet_size
                if idx not in self._free_indices:
                    self._free_indices.append(idx)
                self.quarantined_slots.increment(1)


# ============================================================================
# LOCK-FREE CIRCULAR RING BUFFER
# ============================================================================

class CircularRingBuffer:
    """
    Fixed-size power-of-two capacity array utilizing atomic 64-bit head and tail.
    Stores pure 64-bit integers representing arena slot offsets.
    """

    def __init__(self, capacity: int) -> None:
        # Enforce power-of-two capacity
        if capacity <= 0 or (capacity & (capacity - 1)) != 0:
            raise ValueError("Ring buffer capacity must be a positive power of two.")
        
        self.capacity = capacity
        self.mask = capacity - 1
        
        # Storage array for slot offsets
        self._slots = [0] * capacity
        
        # Atomic sequence indices
        self.head = AtomicCounter64(0)
        self.tail = AtomicCounter64(0)
        
        # Metrics
        self.drop_counter = AtomicCounter64(0)
        self.overflow_counter = AtomicCounter64(0)

    def push(self, slot_offset: int) -> bool:
        """
        Pushes a slot offset into the ring buffer.
        Enforces invariant: tail - head <= capacity.
        Returns True on success, False or raises RingFullError on drop policy.
        """
        while True:
            current_tail = self.tail.get()
            current_head = self.head.get()
            
            if current_tail - current_head >= self.capacity:
                self.overflow_counter.increment(1)
                self.drop_counter.increment(1)
                return False
            
            # Try to claim the tail slot atomically
            if self.tail.compare_and_swap(current_tail, current_tail + 1):
                index = current_tail & self.mask
                self._slots[index] = slot_offset
                return True

    def pop(self) -> Optional[int]:
        """
        Pops a slot offset from the ring buffer.
        Advances the head pointer upon successful consumption.
        """
        while True:
            current_head = self.head.get()
            current_tail = self.tail.get()
            
            if current_head >= current_tail:
                return None  # Ring is empty
            
            index = current_head & self.mask
            slot_offset = self._slots[index]
            
            # Try to advance head atomically
            if self.head.compare_and_swap(current_head, current_head + 1):
                return slot_offset

    def reset_quadrant(self) -> Tuple[int, int]:
        """Resets state of the ring buffer during failure recovery."""
        h = self.head.get()
        t = self.tail.get()
        self.head.set(t)  # Drop all pending in-flight items in the ring
        return h, t


# ============================================================================
# SLIDING-WINDOW FLOW CONTROL & TOKEN BUCKET
# ============================================================================

class SlidingWindowFlowControl:
    """
    Token bucket and sliding window tracking structures enforcing per-flow rate limits,
    congestion mitigation, and sequence validation.
    """

    def __init__(self, rate_limit_rps: float, burst_capacity: int, window_size_sec: float = 1.0) -> None:
        self.rate_limit_rps = float(rate_limit_rps)
        self.burst_capacity = float(burst_capacity)
        self.window_size_sec = float(window_size_sec)
        
        self.tokens = self.burst_capacity
        self.last_refill_time = time.monotonic()
        
        # Flow sequence trackers: flow_id -> last_sequence_number
        self._flow_sequences = {}
        self._lock = threading.Lock()
        
        # Metrics
        self.rate_limited_drops = AtomicCounter64(0)
        self.out_of_order_drops = AtomicCounter64(0)
        self.duplicate_drops = AtomicCounter64(0)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill_time
        self.last_refill_time = now
        
        added_tokens = elapsed * self.rate_limit_rps
        self.tokens = min(self.burst_capacity, self.tokens + added_tokens)

    def check_rate_limit(self) -> bool:
        """Consumes a token from the bucket. Returns True if allowed, False if rate-limited."""
        with self._lock:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            else:
                self.rate_limited_drops.increment(1)
                return False

    def validate_sequence(self, flow_id: int, seq_num: int) -> bool:
        """
        Validates packet sequence number for a flow to drop out-of-order or duplicate packets.
        """
        with self._lock:
            last_seq = self._flow_sequences.get(flow_id)
            if last_seq is None:
                self._flow_sequences[flow_id] = seq_num
                return True
            
            if seq_num == last_seq:
                self.duplicate_drops.increment(1)
                return False
            elif seq_num > last_seq:
                # Handle potential wrap-around or gap checks
                if seq_num - last_seq > 1000000:  # arbitrary large gap check for wrap-around / corruption
                    self.out_of_order_drops.increment(1)
                    return False
                self._flow_sequences[flow_id] = seq_num
                return True
            else:
                # seq_num < last_seq
                self.out_of_order_drops.increment(1)
                return False


# ============================================================================
# NON-BLOCKING POLL LOOPS & SOCKET SELECTORS
# ============================================================================

class PacketFilterEngine:
    """
    Edge-triggered polling architecture utilizing selectors.DefaultSelector
    combined with non-blocking socket abstractions.
    """

    def __init__(self, arena: MemoryArena, ring: CircularRingBuffer, flow_controller: SlidingWindowFlowControl) -> None:
        self.arena = arena
        self.ring = ring
        self.flow_controller = flow_controller
        
        self.selector = selectors.DefaultSelector()
        self._sockets = {}
        self._running = threading.Event()
        self._poll_thread = None
        
        # Metrics
        self.packets_processed = AtomicCounter64(0)
        self.packets_dropped = AtomicCounter64(0)

    def register_socket(self, sock: socket.socket, flow_id: int) -> None:
        """Registers a socket into the non-blocking polling engine."""
        os.set_blocking(sock.fileno(), False)
        self._sockets[sock.fileno()] = (sock, flow_id)
        self.selector.register(sock, selectors.EVENT_READ, data=flow_id)

    def unregister_socket(self, sock: socket.socket) -> None:
        """Unregisters and closes a socket from the polling engine."""
        try:
            self.selector.unregister(sock)
        except Exception:
            pass
        self._sockets.pop(sock.fileno(), None)
        try:
            sock.close()
        except Exception:
            pass

    def start(self) -> None:
        """Starts the background non-blocking polling event loop."""
        if self._running.is_set():
            return
        self._running.set()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True, name="RingFilterPollLoop")
        self._poll_thread.start()

    def stop(self) -> None:
        """Stops the polling event loop and cleans up selectors."""
        self._running.clear()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=2.0)
        self.selector.close()

    def _poll_loop(self) -> None:
        """Edge-triggered event loop for high-throughput packet ingestion."""
        while self._running.is_set():
            try:
                events = self.selector.select(timeout=0.01)
                for key, mask in events:
                    flow_id = key.data
                    sock = key.fileobj
                    
                    if mask & selectors.EVENT_READ:
                        self._handle_read(sock, flow_id)
            except Exception as e:
                # Log or handle unexpected poll exceptions defensively
                time.sleep(0.001)

    def _handle_read(self, sock: socket.socket, flow_id: int) -> None:
        """Reads incoming packet, runs validation, and pushes to ring buffer."""
        try:
            # Allocate slot from memory arena
            slot_offset = self.arena.allocate()
        except ArenaExhaustionError:
            # Arena Exhaustion Guard: backpressure signal upstream, drop packet
            self.packets_dropped.increment(1)
            return

        try:
            slot_view = self.arena.get_view(slot_offset)
            
            # Read packet data directly into memory arena zero-copy buffer view
            # Assuming UDP or raw packet reads where recv_into is supported
            nbytes, _ = sock.recvfrom_into(slot_view)
            
            if nbytes == 0:
                self.arena.release(slot_offset)
                return
            
            # Defensive Boundary Check & Header parsing
            if nbytes < 8:
                # Corrupted or undersized packet header
                self.arena.release(slot_offset)
                self.packets_dropped.increment(1)
                return
            
            # Extract sequence number from the first 8 bytes of payload (big-endian 64-bit int)
            seq_num = int.from_bytes(slot_view[0:8], byteorder='big', signed=False)
            
            # Sliding-Window Flow Control Check
            if not self.flow_controller.check_rate_limit():
                self.arena.release(slot_offset)
                self.packets_dropped.increment(1)
                return
            
            if not self.flow_controller.validate_sequence(flow_id, seq_num):
                self.arena.release(slot_offset)
                self.