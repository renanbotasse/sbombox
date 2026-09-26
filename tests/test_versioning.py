"""version_key / version_cmp / pick_fixed_version / better_fixed_in."""

from __future__ import annotations


from sbombox.versioning import (
    better_fixed_in,
    pick_fixed_version,
    version_cmp,
    version_key,
)


class TestVersionKey:
    def test_simple_ordering(self):
        assert version_cmp("1.0", "1.0.1") < 0
        assert version_cmp("1.9", "1.10") < 0
        assert version_cmp("2.0", "1.99") > 0
        assert version_cmp("1.2.3", "1.2.3") == 0

    def test_empty_and_zero(self):
        assert version_cmp("", "0.1") < 0
        assert version_key("") == version_key("0")
        assert version_key("  ") == version_key(None)  # type: ignore[arg-type]

    def test_v_prefix_epoch_local(self):
        assert version_cmp("v1.2", "1.2") == 0
        assert version_cmp("1!1.0", "2.0") < 0
        assert version_cmp("1.0+abc", "1.0+def") == 0
        assert version_cmp("0.5a2", "0.5b1") < 0

    def test_prerelease_between_releases(self):
        # Loose key semantics: a prerelease sorts above its bare base
        # ("1.0rc1" > "1.0" — documented limitation) but below the next
        # dotted release ("1.0rc1" < "1.0.0", "1.0rc1" < "1.0.1").
        assert version_cmp("1.0rc1", "1.0.0") < 0
        assert version_cmp("1.0rc1", "1.0.1") < 0
        assert version_cmp("1.0a1", "1.0b1") < 0
        assert version_cmp("1.0rc1", "1.0") > 0

    def test_letter_suffix_vs_dot_chunk(self):
        # dot-separated numeric chunk vs letter-suffixed chunk: must NOT crash
        assert version_cmp("2.0a1", "2.0.1") < 0
        assert version_cmp("1.26rc1", "1.26.0") < 0

    def test_regression_mixed_tuple_typeerror(self):
        # Regression: flat int/str tuple comparison crashed with
        # TypeError '<' not supported between 'str' and 'int'.
        assert version_cmp("2.0rc1", "2.0.0rc1") in (-1, 0, 1)
        assert version_cmp("1.0.post1", "1.0.1") < 0

    def test_no_typeerror_for_any_common_pair(self):
        samples = [
            "1.0", "1.0.0", "2.0rc1", "2.0.0rc1", "1.26rc1", "1.26.0",
            "0.5a2", "0.5b1", "3.10.0a1", "3.10", "1.0.post1", "0.0.0",
            "1.0.0.dev0", "2024.1", "v2024.1.1",
        ]
        for a in samples:
            for b in samples:
                assert version_cmp(a, b) in (-1, 0, 1)  # never raises


class TestPickFixedVersion:
    def test_earliest_newer_only(self):
        assert pick_fixed_version("1.0", ["1.0.1", "1.0.2"]) == "1.0.1"

    def test_never_downgrade(self):
        assert pick_fixed_version("2.0", ["1.9", "1.5"]) is None

    def test_prefers_same_minor_line(self):
        assert pick_fixed_version("1.2.0", ["1.3.0", "1.2.1", "2.0.0"]) == "1.2.1"

    def test_prefers_same_major_over_older_minor(self):
        assert pick_fixed_version("1.2.0", ["2.0.0", "1.9.0", "1.5.0"]) == "1.5.0"

    def test_falls_back_to_newest_above(self):
        assert pick_fixed_version("3.0", ["3.0.1", "4.0.0"]) == "3.0.1"

    def test_prerelease_candidates_no_crash(self):
        out = pick_fixed_version("1.26rc1", ["1.26.0rc1", "1.26.0", "1.25.3"])
        assert out in {"1.26.0", "1.26.0rc1"}

    def test_empty_candidates(self):
        assert pick_fixed_version("1.0", []) is None
        assert pick_fixed_version("1.0", [None, "", "  "]) is None

    def test_equal_version_not_picked(self):
        assert pick_fixed_version("1.0", ["1.0"]) is None


class TestBetterFixedIn:
    def test_picks_better_of_two(self):
        assert better_fixed_in("1.2.0", "1.2.1", "1.2.2") == "1.2.1"

    def test_none_handling(self):
        assert better_fixed_in("1.0", None, "1.0.1") == "1.0.1"
        assert better_fixed_in("1.0", "1.0.1", None) == "1.0.1"
        assert better_fixed_in("1.0", None, None) is None