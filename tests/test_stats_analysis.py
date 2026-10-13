import numpy as np

from threatgraph.eval.stats_analysis import paired_ci_95, paired_test


def test_paired_test_identical_systems_zero_diff():
    a = np.array([1.0, 2.0, 3.0, 4.0])
    b = np.array([1.0, 2.0, 3.0, 4.0])
    result = paired_test(a, b)
    assert result["mean_diff_b_minus_a"] == 0.0
    assert result["n"] == 4


def test_paired_test_systematic_improvement():
    a = np.array([5.0, 5.0, 5.0, 5.0, 5.0])
    b = np.array([7.0, 7.0, 7.0, 7.0, 7.0])
    result = paired_test(a, b)
    assert result["mean_diff_b_minus_a"] == 2.0
    assert result["relative_pct_change"] == 40.0


def test_paired_ci_insufficient_data_returns_nan():
    low, high = paired_ci_95(np.array([1.0]))
    assert low != low  # NaN check (NaN != NaN)


def test_paired_ci_contains_mean_for_normal_data():
    rng = np.random.default_rng(0)
    diffs = rng.normal(loc=1.0, scale=0.1, size=100)
    low, high = paired_ci_95(diffs)
    assert low < diffs.mean() < high
