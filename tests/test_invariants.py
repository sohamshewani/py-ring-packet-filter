import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import ring_packet_filter as rpf
except ImportError:
    # Fallback or mock-compatible interface for environments where the native 
    # extension is named or packaged differently, though designed for py-ring-packet-filter.
    import ring_packet_filter as rpf


class TestRingPacketFilterExhaustive(unittest.TestCase):
    """
    Exhaustive unit, invariant, and concurrent stress-test suite for py-ring-packet-filter.
    """

    def setUp(self):
        # Initialize a fresh filter instance with standard sizing for each test
        self.capacity = 1024
        self.filter = rpf.RingFilter(capacity=self.capacity)

    def tearDown(self):
        del self.filter

    # =========================================================================
    # 1. BOUNDARY AND EDGE-CASE ASSERTIONS
    # =========================================================================

    def test_edge_case_zero_and_negative_capacity(self):
        """Verify handling of zero, negative, and invalid capacities."""
        invalid_capacities = [0, -1, -1024, -9223372036854775808]
        for cap in invalid_capacities:
            with self.subTest(capacity=cap):
                with self.assertRaises((ValueError, OverflowError, RuntimeError)):
                    rpf.RingFilter(capacity=cap)

    def test_edge_case_empty_and_max_payloads(self):
        """Verify behavior with empty byte arrays, single bytes, and max-sized payloads."""
        empty_packet = b""
        single_byte = b"\x00"
        max_packet = b"\xff" * 65535  # Standard max UDP-ish size or larger

        # Empty packet insertion
        try:
            res_empty = self.filter.add(empty_packet)
            self.assertIsInstance(res_empty, bool)
        except (ValueError, TypeError):
            # If empty packets are strictly forbidden by design, exception is valid
            pass

        # Single byte insertion
        self.assertTrue(self.filter.add(single_byte))
        self.assertTrue(self.filter.contains(single_byte))

        # Large packet insertion
        self.assertTrue(self.filter.add(max_packet))
        self.assertTrue(self.filter.contains(max_packet))

    def test_edge_case_type_safety(self):
        """Verify that passing incorrect types raises appropriate exceptions."""
        invalid_types = [12345, 123.45, ["packet"], {"data": "packet"}, None]
        for item in invalid_types:
            with self.subTest(item=item):
                with self.assertRaises((TypeError, AttributeError)):
                    self.filter.add(item)  # type: ignore
                with self.assertRaises((TypeError, AttributeError)):
                    self.filter.contains(item)  # type: ignore

    def test_boundary_ring_buffer_wrap_around(self):
        """
        Fill the ring buffer completely and exceed capacity to test FIFO 
        eviction and wrap-around invariants.
        """
        small_filter = rpf.RingFilter(capacity=10)
        
        # Insert 10 unique items (0 to 9)
        packets = [f"packet-{i}".encode("utf-8") for i in range(10)]
        for p in packets:
            small_filter.add(p)

        # All 10 should be present
        for p in packets:
            self.assertTrue(small_filter.contains(p))

        # Insert 5 new items (10 to 14), causing the first 5 to drop out (FIFO eviction)
        new_packets = [f"packet-{i}".encode("utf-8") for i in range(10, 15)]
        for p in new_packets:
            small_filter.add(p)

        # First 5 should now be evicted (not present)
        for i in range(5):
            self.assertFalse(small_filter.contains(packets[i]))

        # Items 5-9 and new items 10-14 should be present
        for i in range(5, 10):
            self.assertTrue(small_filter.contains(packets[i]))
        for p in new_packets:
            self.assertTrue(small_filter.contains(p))

    # =========================================================================
    # 2. INVARIANT VERIFICATION
    # =========================================================================

    def test_invariant_idempotency(self):
        """Inserting the exact same packet multiple times must maintain filter consistency."""
        packet = b"invariant-check-packet"
        
        for _ in range(5):
            self.filter.add(packet)
            self.assertTrue(self.filter.contains(packet))

    def test_invariant_clear_reset(self):
        """Clearing the filter must reset state completely (zero matches post-clear)."""
        packets = [f"clear-test-{i}".encode() for i in range(50)]
        for p in packets:
            self.filter.add(p)

        # Verify presence
        for p in packets:
            self.assertTrue(self.filter.contains(p))

        # Reset / Clear
        if hasattr(self.filter, "clear"):
            self.filter.clear()
            for p in packets:
                self.assertFalse(self.filter.contains(p))
        else:
            # If clear is not exposed, re-initialize
            self.filter = rpf.RingFilter(capacity=self.capacity)
            for p in packets:
                self.assertFalse(self.filter.contains(p))

    # =========================================================================
    # 3. MULTI-THREADED CONTENTION & CONCURRENT STRESS TESTING
    # =========================================================================

    def test_concurrent_heavy_contention(self):
        """
        Spawn multiple threads concurrently writing and reading from the RingFilter
        to detect race conditions, deadlocks, or segmentation faults.
        """
        num_threads = 16
        operations_per_thread = 500
        shared_filter = rpf.RingFilter(capacity=2048)

        errors = []

        def worker(thread_id: int):
            try:
                for i in range(operations_per_thread):
                    payload = f"thread-{thread_id}-packet-{i}".encode("utf-8")
                    # Mix adds and contains
                    shared_filter.add(payload)
                    shared_filter.contains(payload)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f-f"Concurrent execution failed with errors: {errors}")

    def test_concurrent_concurrent_futures_stress(self):
        """
        High-throughput stress test using ThreadPoolExecutor to saturate the filter
        under extreme read/write interleaving.
        """
        stress_capacity = 5000
        stress_filter = rpf.RingFilter(capacity=stress_capacity)
        total_tasks = 10000

        def task(index: int):
            packet = f"stress-{index % 8000}".encode("utf-8")
            if index % 2 == 0:
                stress_filter.add(packet)
            else:
                stress_filter.contains(packet)
            return True

        with ThreadPoolExecutor(max_workers=32) as executor:
            futures = [executor.submit(task, i) for i in range(total_tasks)]
            results = [f.result() for f in as_completed(futures)]

        self.assertEqual(len(results), total_tasks)
        self.assertTrue(all(results))

    # =========================================================================
    # 4. FAILURE AND RECOVERY STATE VERIFICATION
    # =========================================================================

    def test_recovery_under_memory_pressure(self):
        """
        Verify filter stability and recovery after rapid capacity exhaustion 
        and continuous flooding.
        """
        tiny_filter = rpf.RingFilter(capacity=10)

        # Flood with 10,000 items sequentially on a capacity-10 filter
        for i in range(10000):
            packet = f"flood-{i}".encode("utf-8")
            tiny_filter.add(packet)

        # Verify the filter is still responsive and functional post-flood
        recovery_packet = b"recovery-packet-test"
        tiny_filter.add(recovery_packet)
        self.assertTrue(tiny_filter.contains(recovery_packet))

    def test_failure_recovery_invalid_arguments_resilience(self):
        """Ensure that passing invalid inputs does not corrupt the filter state or crash subsequent valid operations."""
        self.filter.add(b"valid-packet-1")
        
        # Inject invalid operations
        for invalid_input in [None, 123, 45.67, ["list"]]:
            try:
                self.filter.add(invalid_input)  # type: ignore
            except (TypeError, ValueError, AttributeError):
                pass

            try:
                self.filter.contains(invalid_input)  # type: ignore
            except (TypeError, ValueError, AttributeError):
                pass

        # Verify filter is still operational after exceptions
        self.assertTrue(self.filter.contains(b"valid-packet-1"))
        
        new_valid = b"valid-packet-2"
        self.filter.add(new_valid)
        self.assertTrue(self.filter.contains(new_valid))


if __name__ == "__main__":
    unittest.main()