import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .scoring_utils import (
    weighted_llm_judge_score,
    codegen_score_from_lm_eval,
    baxbench_score,
    performance_score,
)


def _load_json(path: Path) -> Optional[Any]:
    """Safely load a JSON file from disk, returning None if reading fails."""
    if not path or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _parse_lm_model(obj: Any) -> Optional[str]:
    """
    Extract a model identifier from an lm_eval.json object. Looks for
    metadata.model in per‑task configs and falls back to the model_args
    string. Returns None if no name can be inferred.
    """
    cfgs = obj.get("configs")
    if isinstance(cfgs, dict):
        for v in cfgs.values():
            if isinstance(v, dict):
                m = v.get("metadata", {}).get("model")
                if isinstance(m, str) and m.strip():
                    return m.strip()
    cfg = obj.get("config")
    if isinstance(cfg, dict):
        ma = cfg.get("model_args")
        if isinstance(ma, str) and "model=" in ma:
            try:
                frag = ma.split("model=", 1)[1]
                return frag.split(",", 1)[0].strip()
            except Exception:
                pass
    return None


def _run_id_from_index(root: Path) -> Optional[str]:
    """
    Derive a timestamped identifier from the `generated_at` field in index.json.
    The returned string has the form YYYYMMDDTHHMMSSZ. Returns None on failure.
    """
    idx = _load_json(root / "index.json")
    if isinstance(idx, dict):
        gen = idx.get("generated_at")
        if isinstance(gen, str):
            try:
                dt = gen.replace("Z", "+00:00")
                dt = datetime.fromisoformat(dt)
                return dt.strftime("%Y%m%dT%H%M%SZ")
            except Exception:
                pass
    return None


def _derive_row(
    mdir: Path, model_name: Optional[str], repo_base: Path
) -> Dict[str, Any]:
    """
    Build a leaderboard row for a given model directory by aggregating metrics
    from multiple result JSON files. Metrics include weighted LLM‑judge scores,
    BaxBench results, code generation pass rates, and performance subscores.
    """

    def load(name: str) -> Any:
        p = mdir / f"{name}.json"
        obj = _load_json(p)
        if obj is not None:
            return obj
        idx = _load_json(mdir / "index.json")
        if isinstance(idx, dict):
            for item in idx.get("results", []):
                if str(item.get("name")) == name and item.get("result_path"):
                    rp = Path(item["result_path"])
                    path = rp if rp.is_absolute() else repo_base / rp
                    obj = _load_json(path)
                    if obj is not None:
                        return obj
        return None

    front = load("frontend")
    integ = load("integration_test")
    unit = load("unit_test")
    lm = load("lm_eval")
    index_obj = _load_json(mdir / "index.json")
    bax = load("baxbench")
    row: Dict[str, Any] = {"Model": model_name or ""}
    front_w = {
        "functionality": 0.40,
        "code_quality": 0.25,
        "accessibility": 0.15,
        "error_handling": 0.10,
        "performance": 0.10,
    }
    integ_w = {
        "functionality": 0.40,
        "code_quality": 0.20,
        "performance": 0.20,
        "error_handling": 0.15,
        "accessibility": 0.05,
    }
    unit_w = {
        "functionality": 0.40,
        "code_quality": 0.30,
        "performance": 0.20,
        "error_handling": 0.10,
    }
    f_val = weighted_llm_judge_score(front, front_w) if front is not None else None
    i_val = weighted_llm_judge_score(integ, integ_w) if integ is not None else None
    u_val = weighted_llm_judge_score(unit, unit_w) if unit is not None else None
    row["Frontend (LLM-judge)"] = (
        round(f_val) if isinstance(f_val, (int, float)) else None
    )
    row["Integration Tests (LLM-judge)"] = (
        round(i_val) if isinstance(i_val, (int, float)) else None
    )
    row["Backend (BaxBench)"] = baxbench_score(index_obj, bax)
    row["Unit Tests (LLM-judge)"] = (
        round(u_val) if isinstance(u_val, (int, float)) else None
    )
    row["Codegen (HumanEval/MBPP)"] = codegen_score_from_lm_eval(lm)
    row["Performance"] = performance_score(front, integ)
    numeric = [
        row[c]
        for c in (
            "Frontend (LLM-judge)",
            "Integration Tests (LLM-judge)",
            "Backend (BaxBench)",
            "Unit Tests (LLM-judge)",
            "Codegen (HumanEval/MBPP)",
            "Performance",
        )
        if isinstance(row.get(c), (int, float))
    ]
    row["Overall"] = round(sum(numeric) / len(numeric), 1) if numeric else None
    return row


def _write_leaderboard(out_dir: Path, rows: List[Dict[str, Any]]) -> Path:
    """
    Sort rows by Overall score, assign ranks, and write a CSV to out_dir. Returns the CSV path.
    """
    rows_sorted = sorted(
        rows,
        key=lambda r: (
            r.get("Overall")
            if isinstance(r.get("Overall"), (int, float))
            else -float("inf")
        ),
        reverse=True,
    )
    rank = 1
    for r in rows_sorted:
        r["Rank"] = rank if isinstance(r.get("Overall"), (int, float)) else None
        if r["Rank"]:
            rank += 1
    run_id = _run_id_from_index(out_dir) or "leaderboard"
    csv_path = out_dir / f"{run_id}.csv"
    cols = [
        "Rank",
        "Model",
        "Frontend (LLM-judge)",
        "Integration Tests (LLM-judge)",
        "Backend (BaxBench)",
        "Unit Tests (LLM-judge)",
        "Codegen (HumanEval/MBPP)",
        "Performance",
        "Overall",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        import csv

        w = csv.writer(f)
        w.writerow(cols)
        for row in rows_sorted:
            w.writerow([row.get(c, "") if row.get(c) is not None else "" for c in cols])
    return csv_path


def auto_run(results_root: Optional[os.PathLike | str] = None) -> Dict[str, Any]:
    """
    Entry point for generating a leaderboard from a results directory. If
    results_root is None, attempts to locate a suitable directory under the
    repository base. Returns a dict summarizing status and output locations.
    """
    repo_base = Path(__file__).resolve().parent.parent
    root = Path(results_root) if results_root else None
    if not root:
        for rel_path in (
            "benchmark_app/results/derived",
            "results/derived",
            "benchmark_app/results",
            "results",
        ):
            candidate = repo_base / rel_path
            if candidate.exists():
                root = candidate
                break
    if not root:
        return {"status": "no_results_dir"}
    root = root.resolve()
    dirs = (
        [root]
        if any(root.glob("*.json"))
        else [d for d in root.iterdir() if d.is_dir() and any(d.glob("*.json"))]
        or [root]
    )
    rows: List[Dict[str, Any]] = []
    single_dir_mode = len(dirs) == 1
    for mdir in dirs:
        name = None
        marker = mdir / "model_name.txt"
        if marker.exists():
            try:
                name = marker.read_text(encoding="utf-8").strip() or None
            except Exception:
                name = None
        if not name:
            name = os.environ.get("CODE_SCORE_MODEL_NAME")
        if not name:
            lm_obj = _load_json(mdir / "lm_eval.json")
            name = _parse_lm_model(lm_obj) or None
        if not name and not single_dir_mode:
            name = mdir.name
        rows.append(_derive_row(mdir, name, repo_base))
    csv_p = _write_leaderboard(root, rows)
    return {
        "status": "ok",
        "results_dir": str(root),
        "csv": str(csv_p),
        "rows": len(rows),
    }
