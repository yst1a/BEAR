"""Test test characterize."""
import unittest
import numpy as np
from bear.characterize import characterize_table, certificates, GateEvaluator, characterize
from pathlib import Path
from bear.runtime import NATIVE
import time


class CharacterizeTests(unittest.TestCase):
    def test_unequal_input_domains_are_not_padded_to_square(self):
        a, b = np.indices((4, 32))
        rec = characterize_table(a + b, 5, 6, input_widths=[2, 5])
        self.assertEqual(rec['k_min'], 0)
        self.assertEqual(rec['input_widths'], [2, 5])
        self.assertEqual(rec['metrics']['count'], 128)

    def test_tool_failure_returns_resource_unknown_and_no_retry(self):
        calls = []
        def runner(*args, **kwargs):
            calls.append(args)
            return {'returncode': -9, 'status': 'RESOURCE_UNKNOWN', 'log': str(kwargs['log'])}
        directory = NATIVE / 'characterization' / f'unit_failure_{time.time_ns()}'
        directory.mkdir(parents=True)
        source = directory / 'a.v'
        source.write_text('module a; endmodule', encoding='utf-8')
        rec = characterize([source], 'a', directory / 'out', runner=runner)
        self.assertEqual(rec['status'], 'RESOURCE_UNKNOWN')
        self.assertIsNone(rec['low_local'])
        self.assertFalse(rec['retry'])
        self.assertEqual(len(calls), 1)

    def test_inprocess_memory_failure_is_resource_unknown(self):
        def runner(*args, **kwargs):
            raise MemoryError('Injected memory failure')
        directory = NATIVE / 'characterization' / f'unit_memory_{time.time_ns()}'
        directory.mkdir(parents=True)
        source = directory / 'a.v'
        source.write_text('module a; endmodule', encoding='utf-8')
        rec = characterize([source], 'a', directory / 'out', runner=runner)
        self.assertEqual(rec['status'], 'RESOURCE_UNKNOWN')
        self.assertEqual(rec['resource_scope'], 'inprocess_characterization_memory')
        self.assertFalse(rec['retry'])

    def test_exact_and_modular_exact(self):
        a, b = np.indices((32, 32))
        for ow in (5, 6):
            r = characterize_table((a + b) % (1 << ow), 5, ow)
            self.assertTrue(r["low_local"])
            self.assertEqual(r["k_min"], 0)
            self.assertEqual(r["metrics"]["MED"], 0)
            self.assertEqual(r["t1"]["psi"]["psi_times_D"], [0])

    def test_loa_minimal_boundary_and_exact_lift(self):
        a, b = np.indices((64, 64))
        F = 8 * ((a >> 3) + (b >> 3) + (((a & b) >> 2) & 1)) + ((a | b) & 7)
        r = characterize_table(F, 6, 7)
        self.assertEqual(r["k_min"], 3)
        self.assertTrue(r["t1"]["liftable"])
        self.assertEqual(r["t1"]["psi"]["psi_times_D"], [0, 0, 0, 0, 1, 1, 1, 1])
        self.assertEqual(r["metrics"]["evidence"], "EXHAUSTIVE_FULL_INPUT_DOMAIN")

    def test_nonlocal_high_dependent_error_has_counterexample(self):
        a, b = np.indices((32, 32))
        F = a + b + (((a >> 4) ^ (b >> 4)) & 1)
        r = characterize_table(F, 5, 6)
        self.assertFalse(r["low_local"])
        self.assertEqual(r["counterexample"]["k"], 4)
        c = r["counterexample"]
        self.assertEqual(c["x"] % 16, c["x_prime"] % 16)
        self.assertEqual(c["y"] % 16, c["y_prime"] % 16)

    def test_nonassociative_local_is_not_T1(self):
        phi = np.array([[0, 1], [1, 0]])
        kap = np.array([[0, 0], [0, 0]])
        good = certificates(phi, kap)
        self.assertTrue(good["t1"]["associative"])
        bad = certificates(phi, np.array([[0, 0], [0, 1]]))
        # test test characterize implementation.
        self.assertTrue(bad["t1"]["associative"])
        kap[0, 1] = 1
        bad = certificates(phi, kap)
        self.assertFalse(bad["t1"]["associative"])
        self.assertEqual(bad["t1"]["status"], "FAIL")

    def test_reachable_image_conditions_do_not_promote_full_T1(self):
        # test test characterize implementation.
        phi = np.zeros((4, 4), dtype=int)
        phi[:2, :2] = [[0, 1], [1, 1]]
        phi[2, 3] = 1
        r = certificates(phi, np.zeros_like(phi))
        self.assertEqual(r["t1"]["reachable_image_conditions"]["status"], "PASS")
        self.assertFalse(r["t1"]["associative"])

    def test_row_quotient_of_constant_low_function(self):
        phi, kap = np.zeros((8, 8), int), np.zeros((8, 8), int)
        r = certificates(phi, kap)
        self.assertEqual(r["t2"]["state_count"], 1)
        self.assertEqual(r["t2"]["reps"], [0])

    def test_gate_network(self):
        module = {"ports": {"A": {"direction": "input", "bits": [2]},
                            "B": {"direction": "input", "bits": [3]},
                            "Y": {"direction": "output", "bits": [4, 5]}},
                  "cells": {"metadata": {"type": "$scopeinfo", "connections": {}, "port_directions": {}},
                            "s": {"type": "$_XOR_", "connections": {"A": [2], "B": [3], "Y": [4]},
                                   "port_directions": {"A": "input", "B": "input", "Y": "output"}},
                            "c": {"type": "$_AND_", "connections": {"A": [2], "B": [3], "Y": [5]},
                                   "port_directions": {"A": "input", "B": "input", "Y": "output"}}}}
        got = GateEvaluator(module).evaluate([0, 0, 1, 1], [0, 1, 0, 1])
        self.assertEqual(got.tolist(), [0, 1, 1, 2])


if __name__ == "__main__":
    unittest.main()

