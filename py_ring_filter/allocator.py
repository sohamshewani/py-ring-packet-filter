# -*- coding: utf-8 -*-
"""
py_ring_filter/allocator.py
Production-grade zero-copy Memory Arena and Slot Allocator for py-ring-packet-filter.
Implements pre-allocated contiguous bytearray arenas, fixed-size slot blocks, 
atomic thread-safe lifecycle tracking, and zero-allocation memoryview slicing.
"""

import sys
import ctypes
import threading
from typing import Optional, Tuple

class ArenaExhaustionError(Exception):
    """Raised when the memory arena has no free slots available."""
    pass

class SlotCorruptionError(Exception):
    """Raised when a slot offset or metadata header verification fails."""
    pass

class MemoryArena:
    """
    Manages a contiguous pre-allocated bytearray partitioned into fixed-size slot blocks.
    Enables zero-copy packet handling via direct memoryview offsets and atomic bitmap tracking.
    """

    __slots__ = (
        '_packet_size',
        '_slot_count',
        '_total_size',
        '_arena',
        '_free_list',
        '_allocation_states',
        '_lock',
        '_active_allocations',
        '_exhaustion_counter'
    )

    def __init__(self, packet_size: int, slot_count: int) -> None:
        if packet_size <= 0:
            raise ValueError("packet_size must be greater than zero.")
        if slot_count <= 0 or (slot_count & (slot_count - 1)) != 0:
            raise ValueError("slot_count must be a positive power of two.")

        self._packet_size: int = packet_size
        self._slot_count: int = slot_count
        self._total_size: int = packet_size * slot_count

        # Pre-allocate contiguous memory to eliminate runtime GC and ensure cache locality
        self._arena: bytearray = bytearray(self._total_size)
        
        # Free list tracking available slot indices using an array stack for O(1) ops
        self._free_list: list[int] = list(range(slot_count - 1, -1, -1))
        
        # 0 = Free, 1 = Allocated/In-Flight, 2 = Quarantined
        self._allocation_states: bytearray = bytearray(slot_count)
        
        # Re-entrant lock protecting allocator metadata modifications (free list & state transitions)
        self._lock: threading.Lock = threading.Lock()
        
        self._active_allocations: int = 0
        self._exhaustion_counter: int = 0

    @property
    def packet_size(self) -> int:
        return self._packet_size

    @property
    def slot_count(self) -> int:
        return self._slot_count

    @property
    def total_size(self) -> int:
        return self._total_size

    @property
    def active_allocations(self) -> int:
        with self._lock:
            return self._active_allocations

    @property
    def exhaustion_counter(self) -> int:
        with self._lock:
            return self._exhaustion_counter

    def allocate(self) -> int:
        """
        Allocates a slot from the arena and returns its byte offset.
        Raises ArenaExhaustionError if no free slots are available.
        """
        with self._lock:
            if not self._free_list:
                self._exhaustion_counter += 1
                raise ArenaExhaustionError(
                    f"Memory arena exhausted. Total slots: {self._slot_count}, "
                    f"Active: {self._active_allocations}. Exhaustion count: {self._exhaustion_counter}"
                )

            slot_index = self._free_list.pop()
            
            # Boundary check
            if slot_index < 0 or slot_index >= self._slot_count:
                # Quarantine state trigger
                self._allocation_states[slot_index] = 2 if 0 <= slot_index < self._slot_count else 0
                raise SlotCorruptionError(f"Free list corruption detected: invalid slot index {slot_index}")

            if self._allocation_states[slot_index] != 0:
                raise SlotCorruptionError(f"Slot {slot_index} allocated from free list but state is not 0 (Free).")

            self._allocation_states[slot_index] = 1
            self._active_allocations += 1
            
            offset = slot_index * self._packet_size
            return offset

    def release(self, offset: int) -> None:
        """
        Reclaims an allocated slot back to the free list based on its byte offset.
        Performs strict bounds checking and state validation.
        """
        if offset < 0 or offset >= self._total_size or (offset % self._packet_size) != 0:
            raise SlotCorruptionError(f"Invalid memory offset provided for release: {offset}")

        slot_index = offset // self._packet_size

        with self._lock:
            current_state = self._allocation_states[slot_index]
            
            if current_state != 1:
                raise SlotCorruptionError(
                    f"Attempted to release slot {slot_index} (offset {offset}) "
                    f"which is not in active allocated state (State: {current_state})."
                )

            # Clear slot memory to prevent data leakage between frames
            start = slot_index * self._packet_size
            end = start + self._packet_size
            self._arena[start:end] = b'\x00' * self._packet_size

            self._allocation_states[slot_index] = 0
            self._active_allocations -= 1
            self._free_list.append(slot_index)

    def get_slot_view(self, offset: int, length: Optional[int] = None) -> memoryview:
        """
        Returns a zero-copy memoryview slice pointing directly to the arena offset.
        Enforces strict bounds verification.
        """
        if offset < 0 or offset >= self._total_size or (offset % self._packet_size) != 0:
            raise SlotCorruptionError(f"Invalid offset for memoryview generation: {offset}")

        slot_index = offset // self._packet_size
        
        with self._lock:
            if self._allocation_states[slot_index] == 0:
                raise SlotCorruptionError(f"Attempted to access unallocated slot at offset {offset}.")
            if self._allocation_states[slot_index] == 2:
                raise SlotCorruptionError(f"Attempted to access quarantined slot at offset {offset}.")

        end_offset = offset + (length if length is not None else self._packet_size)
        if end_offset > self._total_size or end_offset > (offset + self._packet_size):
            raise ValueError(f"Requested memoryview length out of bounds for slot size {self._packet_size}.")

        return memoryview(self._arena)[offset:end_offset]

    def quarantine_slot(self, offset: int) -> None:
        """
        Quarantines a corrupt or out-of-bounds slot to isolate failures and trigger recovery.
        """
        if offset < 0 or offset >= self._total_size or (offset % self._packet_size) != 0:
            return

        slot_index = offset // self._packet_size
        with self._lock:
            self._allocation_states[slot_index] = 2 # Quarantined
            # Clear data
            start = slot_index * self._packet_size
            end = start + self._packet_size
            self._arena[start:end] = b'\x00' * self._packet_size
            if self._active_allocations > 0:
                self._active_allocations -= 1

    def reset(self) -> None:
        """
        Performs a full hardware/state reset of the arena, clearing all allocations
        and rebuilding the free list. Used during severe failure recovery modes.
        """
        with self._lock:
            self._arena[:] = b'\x00' * self._total_size
            self._free_list = list(range(self._slot_count - 1, -1, -1))
            self._allocation_states = bytearray(self._slot_count)
            self._active_allocations = 0
            self._exhaustion_counter = 0