from typing import Any, Dict, List, Optional


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


def codegen_score_from_lm_eval(obj: Any) -> Optional[float]:
    """
    Compute a code generation score from an lm_eval result JSON. Extracts pass@1
    metrics and averages them on a 0–100 scale. Returns None if no appropriate
    metrics are found.
    """
    if not obj or not isinstance(obj, dict):
        return None
    results = obj.get("results", {})
    if not isinstance(results, dict) or not results:
        return None
    task_scores: List[float] = []
    for task_blob in results.values():
        if not isinstance(task_blob, dict):
            continue
        for key, val in task_blob.items():
            if not isinstance(val, (int, float)):
                continue
            key_l = str(key).lower()
            if any(sub in key_l for sub in ("pass@1", "pass_at_1", "pass@k")):
                task_scores.append(float(val) * 100.0)
                break
    return None if not task_scores else sum(task_scores) / len(task_scores)


def unit_tests_score_from_test_results(obj: Any) -> Optional[float]:
    """
    Compute a simple pass rate for unit tests based on the number of passed and total tests.
    Returns None if no totals are provided.
    """
    if not obj or not isinstance(obj, dict):
        return None
    ft_passed = obj.get("num_passed_ft")
    ft_total = obj.get("num_total_ft")
    st_total = obj.get("num_total_st")
    st_ex = obj.get("num_st_exceptions")
    if ft_total is None and st_total is None:
        return None
    total = passed = 0
    if isinstance(ft_total, int) and ft_total >= 0:
        total += ft_total
        if isinstance(ft_passed, int):
            passed += max(0, min(ft_passed, ft_total))
    if isinstance(st_total, int) and st_total >= 0:
        total += st_total
        if isinstance(st_ex, int):
            passed += max(0, st_total - st_ex)
    return None if total == 0 else (passed / total) * 100.0


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
    if isinstance(index_obj, dict) and isinstance(index_obj.get("results"), list):
        for item in index_obj["results"]:
            try:
                if item.get("name") == "baxbench":
                    return 80.0 if item.get("status") == "success" else None
            except Exception:
                continue
    return None


def performance_score(front_eval_obj: Any, integ_eval_obj: Any) -> Optional[float]:
    """
    Average the 'performance' subscores from frontend and integration evaluations and scale to 0–100.
    """
    perf_vals: List[float] = []
    for obj in (front_eval_obj, integ_eval_obj):
        if not obj:
            continue
        records = obj if isinstance(obj, list) else [obj]
        for rec in records:
            ev = rec.get("evaluation") if isinstance(rec, dict) else None
            if isinstance(ev, dict) and isinstance(ev.get("performance"), (int, float)):
                perf_vals.append(float(ev["performance"]))
    return None if not perf_vals else (sum(perf_vals) / len(perf_vals)) * 10.0
