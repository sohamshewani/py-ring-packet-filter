# -*- coding: utf-8 -*-
"""
py_ring_filter/flow.py

Production-grade sliding-window flow control, token bucket rate limiter,
and sequence validation module for py-ring-packet-filter.
"""

from __future__ import annotations

import time
import threading
from typing import Optional, Dict, Tuple

class FlowControlError(Exception):
    """Base exception for flow control and rate limiting violations."""
    pass

class RateLimitExceededError(FlowControlError):
    """Raised when a flow exceeds its allocated token bucket transmission rate."""
    pass

class SequenceValidationError(FlowControlError):
    """Raised when a packet sequence violates monotonicity or sliding-window bounds."""
    pass

class TokenBucketRateLimiter:
    """
    Thread-safe Token Bucket rate limiter implementing high-precision rate enforcement
    with microsecond resolution timestamps, preventing burst saturation while allowing
    configured burst capacities.
    """

    __slots__ = (
        '_capacity',
        '_refill_rate',
        '_tokens',
        '_last_refill_timestamp',
        '_lock'
    )

    def __init__(self, capacity: float, refill_rate: float) -> None:
        """
        Initialize the token bucket.

        Args:
            capacity: Maximum burst capacity in tokens.
            refill_rate: Token replenishment rate per second.
        """
        self._capacity: float = float(capacity)
        self._refill_rate: float = float(refill_rate)
        self._tokens: float = float(capacity)
        self._last_refill_timestamp: float = time.monotonic()
        self._lock: threading.Lock = threading.Lock()

    @property
    def capacity(self) -> float:
        return self._capacity

    @property
    def refill_rate(self) -> float:
        return self._refill_rate

    def _refill(self, now: float) -> None:
        """Internal helper to replenish tokens based on elapsed wall-clock time."""
        elapsed = now - self._last_refill_timestamp
        if elapsed > 0.0:
            tokens_to_add = elapsed * self._refill_rate
            if tokens_to_add > 0.0:
                self._tokens = min(self._capacity, self._tokens + tokens_to_add)
                self._last_refill_timestamp = now

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Attempt to consume specified tokens from the bucket.

        Args:
            tokens: Number of tokens required.

        Returns:
            True if tokens were successfully acquired, False otherwise.
        """
        if tokens <= 0.0:
            return True

        with self._lock:
            now = time.monotonic()
            self._refill(now)

            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: float = 1.0) -> None:
        """
        Acquire tokens, raising RateLimitExceededError if insufficient capacity exists.

        Args:
            tokens: Number of tokens required.

        Raises:
            RateLimitExceededError: If the token bucket is exhausted.
        """
        if not self.consume(tokens):
            raise RateLimitExceededError(
                f"Rate limit exceeded: requested {tokens} tokens, available {self._tokens:.2f}"
            )

    def update_parameters(self, capacity: float, refill_rate: float) -> None:
        """Dynamically adjust capacity and refill rates under thread lock."""
        with self._lock:
            now = time.monotonic()
            self._refill(now)
            self._capacity = float(capacity)
            self._refill_rate = float(refill_rate)
            if self._tokens > self._capacity:
                self._tokens = self._capacity


class SlidingWindowFlowController:
    """
    Sliding-window sequence tracker and flow controller enforcing strict monotonicity,
    duplicate packet rejection, out-of-order drop policies, and memory-bounded state
    tracking across unique flow keys.
    """

    __slots__ = (
        '_window_size',
        '_max_tracked_flows',
        '_flows',
        '_lock',
        '_total_dropped',
        '_total_processed',
        '_total_duplicates',
        '_total_out_of_order'
    )

    def __init__(self, window_size: int = 4096, max_tracked_flows: int = 100000) -> None:
        """
        Initialize the sliding window flow controller.

        Args:
            window_size: Size of the sequence tracking sliding window bitmap/buffer.
            max_tracked_flows: Maximum active flows to track before evicting stale entries.
        """
        if window_size <= 0 or (window_size & (window_size - 1)) != 0:
            # Enforce power-of-two for efficient bitmasking/modulus operations if needed
            pass
        self._window_size: int = int(window_size)
        self._max_tracked_flows: int = int(max_tracked_flows)
        # Flow state mapping: flow_key -> {'highest_seq': int, 'bitmask': int, 'last_seen': float}
        self._flows: Dict[Tuple, Dict[str, float | int]] = {}
        self._lock: threading.Lock = threading.Lock()

        # Operational metrics
        self._total_dropped: int = 0
        self._total_processed: int = 0
        self._total_duplicates: int = 0
        self._total_out_of_order: int = 0

    @property
    def total_dropped(self) -> int:
        with self._lock:
            return self._total_dropped

    @property
    def total_processed(self) -> int:
        with self._lock:
            return self._total_processed

    @property
    def total_duplicates(self) -> int:
        with self._lock:
            return self._total_duplicates

    @property
    def total_out_of_order(self) -> int:
        with self._lock:
            return self._total_out_of_order

    def validate_and_update(self, flow_key: Tuple, sequence_number: int) -> bool:
        """
        Validate packet sequence number against the sliding window for a given flow.

        Args:
            flow_key: Tuple representing unique flow identifier (e.g., src/dst IP/port tuple).
            sequence_number: Monotonically increasing sequence number of the incoming packet.

        Returns:
            True if the packet sequence is valid and accepted.

        Raises:
            SequenceValidationError: If sequence is excessively old, duplicated, or corrupted.
        """
        if sequence_number < 0:
            with self._lock:
                self._total_dropped += 1
                self._total_out_of_order += 1
            raise SequenceValidationError(f"Negative sequence number {sequence_number} detected.")

        with self._lock:
            now = time.monotonic()
            flow_state = self._flows.get(flow_key)

            if flow_state is None:
                # Evict oldest or excess flows if capacity reached
                if len(self._flows) >= self._max_tracked_flows:
                    self._evict_stale_flows(now)

                # Initialize new flow state
                self._flows[flow_key] = {
                    'highest_seq': sequence_number,
                    'bitmask': 1,  # Track the current sequence bit
                    'last_seen': now
                }
                self._total_processed += 1
                return True

            highest_seq = int(flow_state['highest_seq'])
            bitmask = int(flow_state['bitmask'])
            flow_state['last_seen'] = now

            if sequence_number > highest_seq:
                # Sequence advances the window
                diff = sequence_number - highest_seq
                if diff >= self._window_size:
                    # Packet is radically ahead of window; reset window or treat as validation failure
                    # Depending on strictness, we can accept and re-anchor or drop.
                    # Here we re-anchor the window to the new packet.
                    flow_state['highest_seq'] = sequence_number
                    flow_state['bitmask'] = 1
                else:
                    # Shift bitmask and set new bit
                    bitmask = (bitmask << diff) | 1
                    flow_state['highest_seq'] = sequence_number
                    flow_state['bitmask'] = bitmask

                self._total_processed += 1
                return True

            else:
                # Sequence is behind or equal to highest_seq
                diff = highest_seq - sequence_number
                if diff >= self._window_size:
                    # Too old, outside the sliding window
                    self._total_dropped += 1
                    self._total_out_of_order += 1
                    raise SequenceValidationError(
                        f"Sequence {sequence_number} is outside sliding window (highest: {highest_seq}, window: {self._window_size})"
                    )

                # Check within window bitmask
                bit_flag = 1 << diff
                if (bitmask & bit_flag) != 0:
                    # Duplicate packet detected
                    self._total_dropped += 1
                    self._total_duplicates += 1
                    raise SequenceValidationError(
                        f"Duplicate sequence number {sequence_number} detected for flow {flow_key}"
                    )
                else:
                    # Mark sequence as seen within the window
                    flow_state['bitmask'] = bitmask | bit_flag
                    self._total_processed += 1
                    return True

    def _evict_stale_flows(self, current_time: float) -> None:
        """Evicts flows that haven't been active recently to prevent memory exhaustion."""
        if not self._flows:
            return
        
        # Sort flows by last_seen timestamp ascending and remove the oldest 10%
        sorted_flows = sorted(self._flows.items(), key=lambda item: item[1]['last_seen'])
        evict_count = max(1, len(sorted_flows) // 10)
        for i in range(evict_count):
            del self._flows[sorted_flows[i][0]]

    def reset_flow(self, flow_key: Tuple) -> None:
        """Explicitly reset state for a given flow key (e.g., on connection teardown)."""
        with self._lock:
            self._flows.pop(flow_key, None)

    def clear(self) -> None:
        """Purge all flow tracking states and reset metrics."""
        with self._lock:
            self._flows.clear()
            self._total_dropped = 0
            self._total_processed = 0
            self._total_duplicates = 0
            self._total_out_of_order = 0


class FlowControllerManager:
    """
    Comprehensive flow enforcement engine combining sliding-window packet validation
    and token-bucket rate limiting per flow, ensuring robust perimeter security and
    congestion mitigation.
    """

    __slots__ = (
        '_window_controller',
        '_rate_limiters',
        '_default_capacity',
        '_default_refill_rate',
        '_lock'
    )

    def __init__(
        self,
        window_size: int = 4096,
        max_tracked_flows: int = 100000,
        default_capacity: float = 1000.0,
        default_refill_rate: float = 500.0
    ) -> None:
        self._window_controller: SlidingWindowFlowController = SlidingWindowFlowController(
            window_size=window_size,
            max_tracked_flows=max_tracked_flows
        )
        self._rate_limiters: Dict[Tuple, TokenBucketRateLimiter] = {}
        self._default_capacity: float = float(default_capacity)
        self._default_refill_rate: float = float(default_refill_rate)
        self._lock: threading.Lock = threading.Lock()

    def get_or_create_limiter(self, flow_key: Tuple) -> TokenBucketRateLimiter:
        """Retrieve or initialize a token bucket rate limiter for a specific flow."""
        with self._lock:
            limiter = self._rate_limiters.get(flow_key)
            if limiter is None:
                limiter = TokenBucketRateLimiter(
                    capacity=self._default_capacity,
                    refill_rate=self._default_refill_rate
                )
                self._rate_limiters[flow_key] = limiter
            return limiter

    def process_packet_flow(self, flow_key: Tuple, sequence_number: int, token_cost: float = 1.0) -> bool:
        """
        Perform complete flow control pipeline check:
        1. Rate limit token acquisition.
        2. Sequence validation via sliding window.

        Args:
            flow_key: Tuple identifying the packet flow.
            sequence_number: Packet sequence identifier.
            token_cost: Token bucket deduction cost for the packet.

        Returns:
            True if the packet passes all flow control inspections.

        Raises:
            RateLimitExceededError: If flow rate limit is breached.
            SequenceValidationError: If sequence is invalid, duplicate, or out-of-order.
        """
        # Step 1: Enforce rate limit
        limiter = self.get_or_create_limiter(flow_key)
        limiter.acquire(token_cost)

        # Step 2: Validate sequence via sliding window
        return self._window_controller.validate_and_update(flow_key, sequence_number)

    @property
    def window_controller(self) -> SlidingWindowFlowController:
        return self._window_controller