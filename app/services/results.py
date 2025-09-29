import csv
from pathlib import Path
from typing import Optional, Tuple, List


class ResultsService:
    """Load benchmark results for the UI.

    Behavior (simple, flexible):
    - If ``results_path`` points to a CSV file, use it.
    - If it points to a directory, try to resolve the latest leaderboard CSV by:
      1) Reading ``latest_models.json`` or ``latest.json`` for a ``csv`` field
      2) Falling back to the newest ``*.csv`` under the directory (recursive)
    - If not provided, fall back to the packaged sample CSV.
    """

    def __init__(self, results_path: Optional[Path | str] = None) -> None:
        app_root = Path(__file__).resolve().parent.parent
        self._default_csv = (app_root / "data" / "leaderboard.csv").resolve()

        if results_path:
            p = Path(results_path)
            if not p.is_absolute():
                p = (app_root / p).resolve()
            try:
                p = p.resolve()
            except Exception:
                pass
            self._input_path: Path = p
        else:
            self._input_path = self._default_csv

    def _from_manifest(self, root: Path) -> Optional[Path]:
        """Try to read a leaderboard CSV path from manifest JSON files in ``root``."""
        import json

        for name in ("latest_models.json", "latest.json"):
            man = root / name
            try:
                if man.exists():
                    obj = json.loads(man.read_text(encoding="utf-8"))
                    csv_val = obj.get("csv") if isinstance(obj, dict) else None
                    if isinstance(csv_val, str) and csv_val:
                        p = Path(csv_val)
                        return p if p.is_absolute() else (root / p).resolve()
            except Exception:
                continue
        return None

    def _newest_csv_under(self, root: Path) -> Optional[Path]:
        try:
            candidates = list(root.rglob("*.csv"))
        except Exception:
            candidates = []
        if not candidates:
            return None
        # Pick the most recently modified CSV
        candidates.sort(key=lambda p: (p.stat().st_mtime if p.exists() else 0), reverse=True)
        return candidates[0]

    def find_latest_csv(self) -> Optional[Path]:
        p = self._input_path
        # Case 1: explicit CSV file path
        if p.exists() and p.is_file() and p.suffix.lower() == ".csv":
            return p
        # Case 2: a manifest file path (latest.json)
        if p.exists() and p.is_file() and p.suffix.lower() == ".json":
            parent = p.parent
            from_manifest = self._from_manifest(parent)
            return from_manifest if from_manifest and from_manifest.exists() else None
        # Case 3: a directory – try manifest then newest CSV
        if p.exists() and p.is_dir():
            from_manifest = self._from_manifest(p)
            if from_manifest and from_manifest.exists():
                return from_manifest
            newest = self._newest_csv_under(p)
            if newest and newest.exists():
                return newest
        # Fallback to the packaged sample CSV
        return self._default_csv if self._default_csv.exists() else None

    def read_results(
        self, max_rows: Optional[int] = 500
    ) -> Tuple[List[str], List[List[str]], Optional[Path]]:
        csv_path = self.find_latest_csv()
        if not csv_path or not csv_path.exists():
            return [], [], None
        with csv_path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        if not rows:
            return [], [], csv_path
        headers, body = rows[0], rows[1:]
        return headers, body[:max_rows] if max_rows else body, csv_path

    def last_updated(self) -> Optional[float]:
        p = self.find_latest_csv()
        try:
            return p.stat().st_mtime if p and p.exists() else None
        except Exception:
            return None
