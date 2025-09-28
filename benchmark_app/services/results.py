import csv
from pathlib import Path
from typing import Optional, Tuple, List


class ResultsService:
    """Load benchmark results from a CSV path or packaged default.

    - If ``results_path`` is provided and points to a file, that CSV is used.
    - Otherwise, falls back to ``benchmark_app/data/leaderboard.csv``.
    """

    def __init__(self, results_path: Optional[Path | str] = None) -> None:
        app_root = Path(__file__).resolve().parent.parent
        default_csv = (app_root / "data" / "leaderboard.csv").resolve()

        chosen: Optional[Path] = None
        if results_path:
            p = Path(results_path)
            if not p.is_absolute():
                p = (app_root / p).resolve()
            try:
                p = p.resolve()
            except Exception:
                pass
            if p.exists() and p.is_file():
                chosen = p

        self.csv_path: Path = chosen or default_csv

    def find_latest_csv(self) -> Optional[Path]:
        return self.csv_path if self.csv_path.exists() else None

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
