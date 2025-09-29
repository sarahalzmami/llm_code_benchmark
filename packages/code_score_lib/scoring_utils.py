from typing import Any, Dict, List, Optional, Iterable


def _norm_key(k: str) -> str:
    """Normalize metric keys for scoring by converting to lower case and replacing separators."""
    nk = str(k).strip().lower().replace(" ", "_").replace("-", "_")
    if nk == "codequality":
        nk = "code_quality"
    if nk == "errorhandling":
        nk = "error_handling"
    return nk


def weighted_llm_judge_score(obj: Any, weights: Dict[str, float]) -> Optional[float]:
    """
    Compute a weighted 0–100 score from LLM‑judge subscores in the `evaluation` field.
    Expects subscores on a 0–10 scale and normalizes the provided weights to the set of
    present subscores. Returns the mean weighted score across records, or None if no
    usable scores are available.
    """
    if not obj:
        return None
    records = obj if isinstance(obj, list) else [obj]
    per_record: List[float] = []
    w_norm = {_norm_key(k): float(v) for k, v in (weights or {}).items()}
    for rec in records:
        eval_block = rec.get("evaluation") if isinstance(rec, dict) else None
        if not isinstance(eval_block, dict):
            continue
        present: Dict[str, float] = {}
        for k, v in eval_block.items():
            if not isinstance(v, (int, float)):
                continue
            present[_norm_key(k)] = float(v)
        usable = {k: w for k, w in w_norm.items() if k in present}
        if not usable:
            continue
        total_w = sum(usable.values())
        if total_w <= 0:
            continue
        avg_0_10 = sum(present[k] * w for k, w in usable.items()) / total_w
        per_record.append(avg_0_10 * 10.0)
    return None if not per_record else sum(per_record) / len(per_record)


def baxbench_score(index_obj: Any, bax_obj: Any) -> Optional[float]:
    """
    Compute a backend score from BaxBench outputs. If numeric values are present,
    averages them and scales into 0–100. Otherwise falls back to index.json status.
    """
    if isinstance(bax_obj, dict):
        numeric_vals = [v for v in bax_obj.values() if isinstance(v, (int, float))]
        if numeric_vals:
            avg = sum(numeric_vals) / len(numeric_vals)
            return avg * 100.0 if 0.0 <= avg <= 1.0 else min(100.0, max(0.0, avg))
    return None


def _iter_eval_blocks(*objs: Any) -> Iterable[Dict[str, float]]:
    """Yield normalized evaluation dicts from result objects.

    - Accepts dicts or lists of dicts; looks for an `evaluation` field.
    - Normalizes keys via `_norm_key` and filters to numeric values.
    """
    for obj in objs:
        if not obj:
            continue
        records = obj if isinstance(obj, list) else [obj]
        for rec in records:
            eval_block = rec.get("evaluation") if isinstance(rec, dict) else None
            if not isinstance(eval_block, dict):
                continue
            out: Dict[str, float] = {}
            for k, v in eval_block.items():
                if isinstance(v, (int, float)):
                    out[_norm_key(k)] = float(v)
            if out:
                yield out


def performance_score(*objs: Any) -> Optional[float]:
    """
    Derive a 0–100 performance score from latency/runtime signals in evaluation blocks.

    Heuristics:
    - Prefer raw timing signals (ms/s): keys containing `latency`, `response_time`,
      `render_time`, `runtime`, `duration`, `ttfb`.
    - Normalize units: `*_ms` -> ms, `*_s` -> seconds; unknown units treated as ms if
      value > 50 else seconds if <= 50, then converted to ms.
    - Aggregate by averaging all found timings across provided objects.
    - Map ms -> score with linear scale where 100ms => 100 and 3000ms => 0, clamped.
    - Fallback: use `performance` subscore (0–10) scaled to 0–100 if no timings.
    """
    evals = list(_iter_eval_blocks(*objs))
    timings_ms: List[float] = []

    def to_ms(key: str, val: float) -> float:
        k = key.lower()
        # Direct unit hints
        if k.endswith("_ms") or "milliseconds" in k or k.endswith("ms"):
            return float(val)
        if k.endswith("_s") or k.endswith("_sec") or "seconds" in k or k.endswith("s"):
            return float(val) * 1000.0
        # Heuristic: values <= 50 are likely seconds (e.g., 0.2, 1.5, 10.0)
        return float(val) * (1000.0 if val <= 50 else 1.0)

    PERF_KEYS = (
        "latency",
        "response_time",
        "render_time",
        "runtime",
        "duration",
        "ttfb",
        "time_to_interactive",
    )
    for ev in evals:
        for k, v in ev.items():
            if any(pk in k for pk in PERF_KEYS):
                timings_ms.append(to_ms(k, v))

    if timings_ms:
        avg_ms = sum(timings_ms) / len(timings_ms)
        # Linear mapping: 100ms => 100, 3000ms => 0
        FAST_MS = 100.0
        SLOW_MS = 3000.0
        if avg_ms <= FAST_MS:
            return 100.0
        if avg_ms >= SLOW_MS:
            return 0.0
        score = 100.0 * (SLOW_MS - avg_ms) / (SLOW_MS - FAST_MS)
        return round(max(0.0, min(100.0, score)))
