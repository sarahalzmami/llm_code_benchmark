import csv
import json
from pathlib import Path
from typing import Optional, Tuple, List


class ResultsService:
    """Encapsulates discovery and loading of benchmark results.

    - Resolves the latest CSV via latest.json manifest or newest runs/<id>.
    - Provides helpers to read CSV rows and expose last-updated time.
    """

    def __init__(self, results_root: Path | str) -> None:
        root = Path(results_root)
        self.root: Path = root.resolve()
        self.manifest_path: Path = self.root / "latest.json"
        self.runs_dir: Path = self.root / "runs"

    def latest_manifest(self) -> dict:
        try:
            if self.manifest_path.exists():
                return json.loads(self.manifest_path.read_text(encoding="utf-8")) or {}
        except Exception as e:
            raise Exception(e)

    def _resolve_csv_from_manifest(self, manifest: dict) -> Optional[Path]:
        csv_path_val = manifest.get("csv") if isinstance(manifest, dict) else None
        if not csv_path_val:
            return None
        p = Path(str(csv_path_val))
        if not p.is_absolute():
            p = self.root / p
        try:
            p = p.resolve()
        except Exception:
            pass
        return p if p.exists() else None

    def find_latest_csv(self) -> Optional[Path]:
        # 1) Look at manifest
        p = self._resolve_csv_from_manifest(self.latest_manifest())
        if p:
            return p
        # 2) Fall back to newest run folder
        try:
            if self.runs_dir.exists():
                runs = sorted(
                    [d for d in self.runs_dir.iterdir() if d.is_dir()],
                    key=lambda d: d.name,
                    reverse=True,
                )
                for d in runs:
                    preferred = d / f"{d.name}.csv"
                    if preferred.exists():
                        return preferred
                    any_csv = next((pp for pp in d.glob("*.csv")), None)
                    if any_csv and any_csv.exists():
                        return any_csv
        except Exception:
            pass
        return None

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
