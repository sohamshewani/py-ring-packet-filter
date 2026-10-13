from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from typing import Final, Optional, Tuple


# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

PACKET_SIZE: Final[int] = 2048
DEFAULT_ARENA_SLOTS: Final[int] = 1024
DEFAULT_RING_CAPACITY: Final[int] = 1024

# Slot allocation states
SLOT_STATE_FREE: Final[int] = 0
SLOT_STATE_ALLOCATED: Final[int] = 1
SLOT_STATE_IN_FLIGHT: Final[int] = 2
SLOT_STATE_QUARANTINED: Final[int] = 3

# Error codes
SUCCESS: Final[int] = 0
ERR_ARENA_EXHAUSTED: Final[int] = -1
ERR_RING_FULL: Final[int] = -2
ERR_RING_EMPTY: Final[int] = -3
ERR_INVALID_OFFSET: Final[int] = -4
ERR_CORRUPTION_DETECTED: Final[int] = -5


# ============================================================================
# EXCEPTION HIERARCHY
# ============================================================================

class RingFilterError(Exception):
    """Base exception for all py-ring-packet-filter failures."""
    pass


class ArenaExhaustedError(RingFilterError):
    """Raised when the memory arena has no free slot blocks available."""
    pass


class RingFullError(RingFilterError):
    """Raised when the circular ring buffer has reached max capacity."""
    pass


class RingEmptyError(RingFilterError):
    """Raised when attempting to read from an empty ring buffer."""
    pass


class MemoryCorruptionError(RingFilterError):
    """Raised when out-of-bounds access or structural corruption is detected."""
    pass


class FlowControlViolationError(RingFilterError):
    """Raised when flow control checks, rate limits, or sequence validations fail."""
    pass


# ============================================================================
# ATOMIC PRIMITIVES & THREAD-SAFETY MONITORS
# ============================================================================

class AtomicCounter64:
    """Thread-safe 64-bit monotonically increasing atomic counter using locks."""
    
    __slots__ = ('_value', '_lock')

    def __init__(self, initial: int = 0) -> None:
        self._value = int(initial)
        self._lock = threading.Lock()

    def get(self) -> int:
        with self._lock:
            return self._value

    def increment(self, amount: int = 1) -> int:
        with self._lock:
            self._value += amount
            return self._value

    def set(self, value: int) -> None:
        with self._lock:
            self._value = value

    def compare_and_swap(self, expected: int, desired: int) -> bool:
        with self._lock:
            if self._value == expected:
                self._value = desired
                return True
            return False


# ============================================================================
# MEMORY ARENA
# ============================================================================

class MemoryArena:
    """
    Pre-allocated contiguous bytearray partitioned into fixed-size slot blocks
    (PACKET_SIZE) to eliminate runtime GC overhead and enable zero-copy packet
    handling via memory offsets.
    """

    __slots__ = (
        '_capacity_slots',
        '_slot_size',
        '_total_size',
        '_raw_buffer',
        '_slot_states',
        '_lock',
        '_exhaustion_count',
        '_corruption_count'
    )

    def __init__(self, capacity_slots: int = DEFAULT_ARENA_SLOTS, slot_size: int = PACKET_SIZE) -> None:
        if capacity_slots <= 0 or (capacity_slots & (capacity_slots - 1)) != 0:
            raise ValueError("Arena capacity_slots must be a positive power of two.")
        if slot_size <= 0:
            raise ValueError("Slot size must be greater than zero.")

        self._capacity_slots: Final[int] = capacity_slots
        self._slot_size: Final[int] = slot_size
        self._total_size: Final[int] = capacity_slots * slot_size

        # Pre-allocate contiguous bytearray
        self._raw_buffer = bytearray(self._total_size)
        
        # Track slot allocation and safety states
        self._slot_states = bytearray(capacity_slots)
        for i in range(capacity_slots):
            self._slot_states[i] = SLOT_STATE_FREE

        self._lock = threading.Lock()
        self._exhaustion_count = AtomicCounter64(0)
        self._corruption_count = AtomicCounter64(0)

    @property
    def capacity_slots(self) -> int:
        return self._capacity_slots

    @property
    def slot_size(self) -> int:
        return self._slot_size

    @property
    def total_size(self) -> int:
        return self._total_size

    def allocate_slot(self) -> int:
        """
        Finds a free slot, marks it as allocated, and returns its byte offset.
        Raises ArenaExhaustedError if no slots are available.
        """
        with self._lock:
            for idx in range(self._capacity_slots):
                if self._slot_states[idx] == SLOT_STATE_FREE:
                    self._slot_states[idx] = SLOT_STATE_ALLOCATED
                    return idx * self._slot_size

        self._exhaustion_count.increment(1)
        raise ArenaExhaustedError("Memory arena exhausted: all slot blocks are pinned or active.")

    def pin_slot_in_flight(self, offset: int) -> None:
        """Transitions a slot state to in-flight while traversing the ring buffer."""
        idx = self._validate_and_get_index(offset)
        with self._lock:
            current_state = self._slot_states[idx]
            if current_state == SLOT_STATE_QUARANTINED:
                raise MemoryCorruptionError(f"Attempted to use quarantined slot at offset {offset}")
            self._slot_states[idx] = SLOT_STATE_IN_FLIGHT

    def release_slot(self, offset: int) -> None:
        """Reclaims a slot after consumer acknowledgment, resetting its state to free."""
        idx = self._validate_and_get_index(offset)
        with self._lock:
            self._slot_states[idx] = SLOT_STATE_FREE

    def quarantine_slot(self, offset: int) -> None:
        """Quarantines a corrupt slot to prevent further processing."""
        self._corruption_count.increment(1)
        try:
            idx = self._validate_and_get_index(offset)
            with self._lock:
                self._slot_states[idx] = SLOT_STATE_QUARANTINED
        except Exception:
            pass  # Fallback safety if offset is completely out of bounds

    def get_memoryview(self, offset: int, length: Optional[int] = None) -> memoryview:
        """Returns a zero-copy memoryview slice for a specific slot offset."""
        idx = self._validate_and_get_index(offset)
        end_offset = offset + (length if length is not None else self._slot_size)
        if end_offset > self._total_size:
            self.quarantine_slot(offset)
            raise MemoryCorruptionError(f"Memoryview slice out of bounds: offset {offset}, length {length}")
        return memoryview(self._raw_buffer)[offset:end_offset]

    def _validate_and_get_index(self, offset: int) -> int:
        if offset < 0 or offset >= self._total_size or offset % self._slot_size != 0:
            self._corruption_count.increment(1)
            raise MemoryCorruptionError(f"Invalid arena byte offset: {offset}")
        return offset // self._slot_size

    def get_metrics(self) -> Tuple[int, int, int]:
        """Returns (exhaustion_count, corruption_count, free_slots_count)."""
        with self._lock:
            free_count = sum(1 for state in self._slot_states if state == SLOT_STATE_FREE)
        return (self._exhaustion_count.get(), self._corruption_count.get(), free_count)


# ============================================================================
# LOCK-FREE CIRCULAR RING BUFFER
# ============================================================================

class CircularRingBuffer:
    """
    Fixed-size power-of-two capacity array utilizing atomic 64-bit monotonically
    increasing head and tail sequence indices. Stores pure 64-bit integers
    representing arena slot offsets.
    """

    __slots__ = (
        '_capacity',
        '_mask',
        '_slots',
        '_head',
        '_tail',
        '_drop_count',
        '_lock'
    )

    def __init__(self, capacity: int = DEFAULT_RING_CAPACITY) -> None:
        if capacity <= 0 or (capacity & (capacity - 1)) != 0:
            raise ValueError("Ring capacity must be a positive power of two.")

        self._capacity: Final[int] = capacity
        self._mask: Final[int] = capacity - 1
        
        # Array storing slot offsets (64-bit integers)
        self._slots = (ctypes.c_uint64 * capacity)()
        for i in range(capacity):
            self._slots[i] = 0

        self._head = AtomicCounter64(0)
        self._tail = AtomicCounter64(0)
        self._drop_count = AtomicCounter64(0)
        self._lock = threading.Lock()

    @property
    def capacity(self) -> int:
        return self._capacity

    def size(self) -> int:
        tail_val = self._tail.get()
        head_val = self._head.get()
        if tail_val >= head_val:
            return tail_val - head_val
        return 0

    def push(self, slot_offset: int) -> None:
        """
        Pushes a slot offset into the ring buffer. Enforces invariant:
        tail - head <= capacity. Implements ring-full drop-policy.
        """
        with self._lock:
            tail_val = self._tail.get()
            head_val = self._head.get()

            # Invariant check: tail - head <= capacity
            if (tail_val - head_val) >= self._capacity:
                self._drop_count.increment(1)
                raise RingFullError("Ring buffer full: tail-drop policy triggered.")

            index = tail_val & self._mask
            self._slots[index] = ctypes.c_uint64(slot_offset)
            self._tail.increment(1)

    def pop(self) -> int:
        """
        Pops a slot offset from the ring buffer. Raises RingEmptyError if empty.
        Advances the head pointer upon successful consumption.
        """
        with self._lock:
            head_val = self._head.get()
            tail_val = self._tail.get()

            if head_val >= tail_val:
                raise RingEmptyError("Ring buffer is empty.")

            index = head_val & self._mask
            slot_offset = int(self._slots[index])
            self._head.increment(1)
            return slot_offset

    def peek(self) -> int:
        """Peeks at the next slot offset without advancing the head pointer."""
        with self._lock:
            head_val = self._head.get()
            tail_val = self._tail.get()

            if head_val >= tail_val:
                raise RingEmptyError("Ring buffer is empty.")

            index = head_val & self._mask
            return int(self._slots[index])

    @property
    .drop_count(self) -> int:
        return self._drop_count.get()


# ============================================================================
# SLIDING-WINDOW FLOW CONTROL & TOKEN BUCKET
# ============================================================================

class TokenBucketRateLimiter:
    """Token bucket rate limiter enforcing per-flow bandwidth and rate limits."""

    __slots__ = (
        '_capacity',
        '_refill_rate',
        '_tokens',
        '_last_refill_timestamp',
        '_lock'
    )

    def __init__(self, capacity: float, refill_rate: float) -> None:
        if capacity <= 0 or refill_rate <= 0:
            raise ValueError("Token bucket capacity and refill rate must be positive.")
        self._capacity: Final[float] = float(capacity)
        self._refill_rate: Final[float] = float(refill_rate)
        self._tokens = float(capacity)
        self._last_refill_timestamp = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: float = 1.0) -> bool:
        """Attempts to consume tokens. Returns True if successful, False otherwise."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill_timestamp
            self._last_refill_timestamp = now

            # Refill tokens based on elapsed time
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class SlidingWindowFlowController:
    """
    Sliding window flow control tracking structure enforcing per-flow rate limits,
    congestion mitigation, and sequence validation to drop out-of-order or duplicate packets.
    """

    __slots__ = (
        '_window_size_seconds',
        '_max_packets_per_window',
        '_seen_sequences',
        '_packet_timestamps',
        '_rate_limiter',
        '_lock',
        '_out_of_order_drops',
        '_duplicate_drops',
        '_rate_limit_drops',
        '_last_validated_sequence'
    )

    def __init__(
        self,
        window_size_seconds: float = 1.0,
        max_packets_per_window: int = 10000,
        refill_rate: Optional[float] = None
    ) -> None:
        if window_size_seconds <= 0 or max_packets_per_window <= 0:
            raise ValueError("Window size and max packets must be positive.")

        self._window_size_seconds: Final[float] = float(window_size_seconds)
        self._max_packets_per_window: Final[int] = int(max_packets_per_window)
        
        # Flow tracking states
        self._seen_sequences = set()
        self._packet_timestamps = []
        
        # Token bucket integration for granular rate limiting
        limiter_rate = refill_rate if refill_rate is not None else (max_packets_per_window / window_size_seconds)
        self._rate_limiter = TokenBucketRateLimiter(capacity=max_packets_per_window, refill_rate=limiter_rate)
        
        self._lock = threading.Lock()
        self._out_of_order_drops = AtomicCounter64(0)
        self._duplicate_drops = AtomicCounter64(0)
        self._rate_limit_drops = AtomicCounter64(0)
        self._last_validated_sequence: Optional[int] = None

    def validate_and_track(self, sequence_number: int) -> bool:
        """
        Validates packet sequence monotonicity, detects duplicates, checks sliding window,
        and enforces token bucket rate limits. Returns True if packet is accepted,
        False if dropped.
        """
        with self._lock:
            now = time.monotonic()

            # 1. Rate limit check via token bucket
            if not self._rate_limiter.consume(1.0):
                self._rate_limit_drops.increment(1)
                return False

            # 2. Sequence validation & duplicate detection
            if sequence_number in self._seen_sequences:
                self._duplicate_drops.increment(1)
                return False

            if self._last_validated_sequence is not None:
                if sequence_number <= self._last_validated_sequence:
                    # Strict monotonicity violation or out-of-order packet
                    self._out_of_order_drops.increment(1)
                    return False

            # 3. Sliding window timestamp pruning
            cutoff = now - self._window_size_seconds
            while self._packet_timestamps and self._packet_timestamps[0][0] < cutoff:
                _, old_seq = self._packet_timestamps.pop(0)
                self._seen_sequences.discard(old_seq)

            # Enforce max packets per window bound
            if len(self._