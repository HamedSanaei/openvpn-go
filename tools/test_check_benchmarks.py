"""Tests for the release benchmark gate."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from check_benchmarks import LIMITS, check


class BenchmarkCheck(unittest.TestCase):
    def measurements(self, change=None, counts=None):
        lines = []
        for name, metrics in LIMITS.items():
            for position in range(3):
                pairs = []
                for unit, limit in metrics.items():
                    value = str(limit if unit != "allocs/op" else 0)
                    if change:
                        value = change(name, unit, position, value)
                    pairs.extend((value, unit))
                count = counts[position] if counts else "100"
                lines.append(f"{name}-8 {count} {' '.join(pairs)}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benchmarks.txt"
            path.write_text("\n".join(lines), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                return check(path)

    def test_valid_exact_limits_and_zero_allocations(self):
        self.assertEqual(self.measurements(), [])

    def test_iteration_counts(self):
        self.assertEqual(self.measurements(counts=["1", "100", "10000000"]), [])
        for invalid in ("zero", "0", "000", "-1", "+5", "1.5", "24e3", "NaN", "1_000", "１２"):
            for position in range(3):
                with self.subTest(count=invalid, sample=position):
                    counts = ["100"] * 3
                    counts[position] = invalid
                    with self.assertRaisesRegex(ValueError, "line .*invalid benchmark iteration count"):
                        self.measurements(counts=counts)

    def test_invalid_measurements_anywhere(self):
        for invalid in ("NaN", "inf", "-inf", "-1"):
            for row in range(3):
                for target, metrics in LIMITS.items():
                    for metric in metrics:
                        with self.subTest(value=invalid, sample=row, benchmark=target, metric=metric):
                            def change(name, unit, position, value):
                                return invalid if (name, unit, position) == (target, metric, row) else value

                            with self.assertRaisesRegex(ValueError, "invalid .* measurement"):
                                self.measurements(change)

    def test_valid_outlier_keeps_median(self):
        def change(name, unit, position, value):
            return "1000000000" if unit == "ns/op" and position == 0 else value

        self.assertEqual(self.measurements(change), [])

    def test_valid_median_above_limit_fails(self):
        def change(name, unit, position, value):
            return "1000000000" if unit == "ns/op" and position <= 1 else value

        self.assertEqual(len(self.measurements(change)), len(LIMITS))


if __name__ == "__main__":
    unittest.main()
