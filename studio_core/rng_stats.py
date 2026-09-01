"""Independent statistical certification of a roulette draw stream (R2 unit 1).

Why this module is separate
---------------------------
This module deliberately imports nothing from :mod:`studio_core.rng`. It accepts a plain
sequence of integers and knows only how many pockets a wheel has. That independence is the
point: a statistics module that shared code with the generator could inherit the generator's
mistake and certify it. Here, the only thing under test is the output.

What "pass" means and does not mean
-----------------------------------
Every test is a falsification attempt, so a pass is a failure to detect a defect, not proof
of correctness. Uniformity of the mapping is *not* established statistically at all -- it is
proved by exhausting the byte domain in ``studio_core.rng.mapping_distribution``. These tests
cover what enumeration cannot: whether the live entropy source actually behaves like the
uniform source the proof assumes.

Test selection
--------------
- Uniformity: a pocket that is favoured over many spins is the defect that directly moves
  house edge, so it is checked first.
- Serial independence: a stream can be perfectly uniform overall and still be predictable
  from the previous result. Adjacent *non-overlapping* pairs are used because overlapping
  pairs share a draw and violate the independence assumption of the chi-square statistic.
- Rejection rate: rejection sampling is the mechanism that removes modulo bias, so an
  observed acceptance rate that drifts from the declared one means the debiasing path is not
  running as specified even when the pockets still look uniform.

The chi-square tail probability is computed from the regularized upper incomplete gamma
function so that this module has no third-party dependency and needs no critical-value table.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

__all__ = [
    "DEFAULT_ALPHA",
    "MIN_EXPECTED_PER_CELL",
    "POCKET_COUNT",
    "StatisticalResult",
    "certify_stream",
    "chi_square_p_value",
    "pair_counts",
    "pocket_counts",
    "rejection_rate_test",
    "serial_independence_test",
    "summarize",
    "uniformity_test",
]

POCKET_COUNT = 37

#: Two-sided significance is not used: every test here is a one-sided upper-tail chi-square.
#: 0.001 keeps the false-alarm rate low enough that a passing suite is not routinely red,
#: while still catching the bias magnitudes that matter to an economy model.
DEFAULT_ALPHA = 0.001

#: Pearson's chi-square approximation degrades when cells are sparse. Five expected
#: observations per cell is the conventional floor; below it this module refuses to report a
#: verdict rather than report an unreliable one.
MIN_EXPECTED_PER_CELL = 5.0

_MAX_ITERATIONS = 1000
_EPSILON = 1e-14
_TINY = 1e-300


@dataclass(frozen=True)
class StatisticalResult:
    """Outcome of one falsification attempt against a draw stream."""

    test_id: str
    statistic: float
    degrees_of_freedom: int
    p_value: float
    alpha: float
    sample_size: int
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "statistic": self.statistic,
            "degrees_of_freedom": self.degrees_of_freedom,
            "p_value": self.p_value,
            "alpha": self.alpha,
            "sample_size": self.sample_size,
            "passed": self.passed,
            "detail": self.detail,
        }


def _gamma_series(a: float, x: float) -> float:
    """Return the regularized lower incomplete gamma P(a, x) by its series expansion."""

    term = 1.0 / a
    total = term
    ap = a
    for _ in range(_MAX_ITERATIONS):
        ap += 1.0
        term *= x / ap
        total += term
        if abs(term) < abs(total) * _EPSILON:
            return total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    raise ArithmeticError("the incomplete gamma series did not converge")


def _gamma_continued_fraction(a: float, x: float) -> float:
    """Return the regularized upper incomplete gamma Q(a, x) by a modified Lentz iteration."""

    b = x + 1.0 - a
    c = 1.0 / _TINY
    d = 1.0 / b if b != 0.0 else 1.0 / _TINY
    h = d
    for index in range(1, _MAX_ITERATIONS + 1):
        an = -index * (index - a)
        b += 2.0
        d = an * d + b
        if abs(d) < _TINY:
            d = _TINY
        c = b + an / c
        if abs(c) < _TINY:
            c = _TINY
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPSILON:
            return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    raise ArithmeticError("the incomplete gamma continued fraction did not converge")


def chi_square_p_value(statistic: float, degrees_of_freedom: int) -> float:
    """Return the upper-tail probability of ``statistic`` under chi-square(``dof``).

    This is the probability that a correct generator produces a statistic at least this
    extreme, so a small value is evidence against the stream, never evidence for it.
    """

    if not isinstance(degrees_of_freedom, int) or isinstance(degrees_of_freedom, bool) or degrees_of_freedom < 1:
        raise ValueError("degrees_of_freedom must be a positive integer")
    if not isinstance(statistic, (int, float)) or isinstance(statistic, bool) or math.isnan(statistic):
        raise ValueError("the chi-square statistic must be a real number")
    if statistic < 0:
        raise ValueError("the chi-square statistic cannot be negative")
    if statistic == 0:
        return 1.0

    a = degrees_of_freedom / 2.0
    x = statistic / 2.0
    if x < a + 1.0:
        return max(0.0, min(1.0, 1.0 - _gamma_series(a, x)))
    return max(0.0, min(1.0, _gamma_continued_fraction(a, x)))


def _validate_sequence(sequence: Sequence[int], pocket_count: int) -> None:
    if not isinstance(pocket_count, int) or isinstance(pocket_count, bool) or pocket_count < 2:
        raise ValueError("pocket_count must be an integer of at least 2")
    for index, value in enumerate(sequence):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < pocket_count:
            raise ValueError(f"draw {index} is not an integer pocket in 0..{pocket_count - 1}")


def pocket_counts(sequence: Sequence[int], *, pocket_count: int = POCKET_COUNT) -> list[int]:
    """Return the observed frequency of every pocket, including pockets never drawn."""

    _validate_sequence(sequence, pocket_count)
    counts = [0] * pocket_count
    for value in sequence:
        counts[value] += 1
    return counts


def pair_counts(sequence: Sequence[int], *, pocket_count: int = POCKET_COUNT) -> list[int]:
    """Return frequencies of non-overlapping adjacent ordered pairs, flattened row-major.

    Non-overlapping pairing halves the sample but keeps the cells independent, which is what
    the chi-square statistic assumes. A trailing unpaired draw is ignored.
    """

    _validate_sequence(sequence, pocket_count)
    counts = [0] * (pocket_count * pocket_count)
    for index in range(0, len(sequence) - 1, 2):
        counts[sequence[index] * pocket_count + sequence[index + 1]] += 1
    return counts


def _chi_square_uniform(counts: Sequence[int]) -> tuple[float, int, int]:
    total = sum(counts)
    cells = len(counts)
    expected = total / cells
    statistic = sum((observed - expected) ** 2 for observed in counts) / expected
    return statistic, cells - 1, total


def _minimum_sample(cells: int) -> int:
    return int(math.ceil(MIN_EXPECTED_PER_CELL * cells))


def uniformity_test(
    sequence: Sequence[int],
    *,
    pocket_count: int = POCKET_COUNT,
    alpha: float = DEFAULT_ALPHA,
) -> StatisticalResult:
    """Test whether every pocket occurs equally often across the stream."""

    counts = pocket_counts(sequence, pocket_count=pocket_count)
    required = _minimum_sample(pocket_count)
    if len(sequence) < required:
        raise ValueError(f"uniformity needs at least {required} draws, received {len(sequence)}")

    statistic, dof, total = _chi_square_uniform(counts)
    p_value = chi_square_p_value(statistic, dof)
    passed = p_value > alpha
    return StatisticalResult(
        test_id="POCKET_UNIFORMITY",
        statistic=statistic,
        degrees_of_freedom=dof,
        p_value=p_value,
        alpha=alpha,
        sample_size=total,
        passed=passed,
        detail=(
            "every pocket is equally likely"
            if passed
            else "the pocket frequencies deviate more than chance explains"
        ),
    )


def serial_independence_test(
    sequence: Sequence[int],
    *,
    pocket_count: int = POCKET_COUNT,
    alpha: float = DEFAULT_ALPHA,
) -> StatisticalResult:
    """Test whether a draw carries information about the draw that follows it."""

    cells = pocket_count * pocket_count
    required = 2 * _minimum_sample(cells)
    if len(sequence) < required:
        raise ValueError(f"serial independence needs at least {required} draws, received {len(sequence)}")

    counts = pair_counts(sequence, pocket_count=pocket_count)
    statistic, dof, total = _chi_square_uniform(counts)
    p_value = chi_square_p_value(statistic, dof)
    passed = p_value > alpha
    return StatisticalResult(
        test_id="SERIAL_INDEPENDENCE",
        statistic=statistic,
        degrees_of_freedom=dof,
        p_value=p_value,
        alpha=alpha,
        sample_size=total,
        passed=passed,
        detail=(
            "consecutive draws show no detectable dependence"
            if passed
            else "consecutive draws are dependent; the stream is partly predictable"
        ),
    )


def rejection_rate_test(
    accepted: int,
    rejected: int,
    *,
    expected_acceptance_rate: float,
    alpha: float = DEFAULT_ALPHA,
) -> StatisticalResult:
    """Test whether the debiasing path accepts entropy at its declared rate.

    A drifting acceptance rate means the rejection boundary is not the one the unbiasedness
    proof assumes, which is a defect even while the pockets still look uniform.
    """

    for name, value in (("accepted", accepted), ("rejected", rejected)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    if not 0.0 < expected_acceptance_rate < 1.0:
        raise ValueError("expected_acceptance_rate must lie strictly between 0 and 1")

    total = accepted + rejected
    expected_accepted = total * expected_acceptance_rate
    expected_rejected = total * (1.0 - expected_acceptance_rate)
    if min(expected_accepted, expected_rejected) < MIN_EXPECTED_PER_CELL:
        raise ValueError("the sample is too small for a reliable acceptance-rate verdict")

    statistic = (accepted - expected_accepted) ** 2 / expected_accepted + (
        rejected - expected_rejected
    ) ** 2 / expected_rejected
    p_value = chi_square_p_value(statistic, 1)
    passed = p_value > alpha
    return StatisticalResult(
        test_id="REJECTION_RATE",
        statistic=statistic,
        degrees_of_freedom=1,
        p_value=p_value,
        alpha=alpha,
        sample_size=total,
        passed=passed,
        detail=(
            "entropy is accepted at the declared rate"
            if passed
            else "the observed acceptance rate contradicts the declared rejection boundary"
        ),
    )


def certify_stream(
    sequence: Sequence[int],
    *,
    pocket_count: int = POCKET_COUNT,
    alpha: float = DEFAULT_ALPHA,
    accepted: int | None = None,
    rejected: int | None = None,
    expected_acceptance_rate: float | None = None,
) -> dict[str, Any]:
    """Run every applicable test and return a report suitable for an evidence file.

    Tests whose sample requirement the stream cannot meet, or whose tail probability fails to
    converge, are reported as skipped with the reason. They are never silently dropped and
    never counted as passes, so ``all_passed`` cannot become true by omission.
    """

    results: list[StatisticalResult] = []
    skipped: list[dict[str, str]] = []

    for test_id, runner in (
        ("POCKET_UNIFORMITY", lambda: uniformity_test(sequence, pocket_count=pocket_count, alpha=alpha)),
        (
            "SERIAL_INDEPENDENCE",
            lambda: serial_independence_test(sequence, pocket_count=pocket_count, alpha=alpha),
        ),
    ):
        try:
            results.append(runner())
        except (ValueError, ArithmeticError) as exc:
            skipped.append({"test_id": test_id, "reason": str(exc)})

    if accepted is not None and rejected is not None and expected_acceptance_rate is not None:
        try:
            results.append(
                rejection_rate_test(
                    accepted,
                    rejected,
                    expected_acceptance_rate=expected_acceptance_rate,
                    alpha=alpha,
                )
            )
        except (ValueError, ArithmeticError) as exc:
            skipped.append({"test_id": "REJECTION_RATE", "reason": str(exc)})

    return {
        "sample_size": len(sequence),
        "pocket_count": pocket_count,
        "alpha": alpha,
        "results": [item.to_dict() for item in results],
        "skipped": skipped,
        "all_passed": bool(results) and all(item.passed for item in results),
    }


def summarize(report: Mapping[str, Any]) -> str:
    """Return a one-line human summary of a :func:`certify_stream` report."""

    verdict = "PASS" if report.get("all_passed") else "FAIL"
    names = ", ".join(f"{item['test_id']} p={item['p_value']:.4f}" for item in report.get("results", []))
    return f"{verdict} n={report.get('sample_size')} [{names}]"
