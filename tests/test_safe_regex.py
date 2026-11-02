from __future__ import annotations

import time
import unittest

import safe_regex as re


class SafeRegexTests(unittest.TestCase):
    def test_catastrophic_pattern_is_bounded(self) -> None:
        started = time.perf_counter()
        result = re.search(r"(a+)+$", "a" * 80_000 + "!")
        elapsed = time.perf_counter() - started

        self.assertIsNone(result)
        self.assertLess(elapsed, 0.25)

    def test_compiled_pattern_preserves_match_and_substitution_contract(self) -> None:
        pattern = re.compile(r"(?P<name>[A-Za-z]+)-(?P<count>\d+)", re.I)
        match = pattern.fullmatch("Widget-42")

        self.assertIsNotNone(match)
        self.assertEqual(match.group("name"), "Widget")
        self.assertEqual(match.group("count"), "42")
        self.assertEqual(pattern.sub(r"\g<name>", "Widget-42"), "Widget")

    def test_timeout_fallbacks_do_not_transform_or_expand_input(self) -> None:
        payload = "a" * 80_000 + "!"
        pattern = re.compile(r"(a+)+$")

        self.assertEqual(pattern.findall(payload), [])
        self.assertEqual(list(pattern.finditer(payload)), [])
        self.assertEqual(pattern.split(payload), [payload])
        self.assertEqual(pattern.sub("changed", payload), payload)


if __name__ == "__main__":
    unittest.main()
