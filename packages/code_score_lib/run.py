from __future__ import annotations
import importlib, json, os, shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Protocol

from .benchmarks.base.benchmark import Benchmark
from .exceptions import SkipBenchmark
from .utils import ensure_dir, exc_str, rel, write_json
from .leaderboard_utils import auto_run


class BenchmarkRunner:
    """Single place to orchestrate benchmark runs and leaderboard builds."""

    class BenchmarkKind(str, Enum):
        dspy = "dspy"
        lm_eval = "lm_eval"
        bax_bench = "bax_bench"

    @dataclass
    class RuntimePaths:
        tasks_directory: Path
        outputs_directory: Path
        results_directory: Path

    @dataclass
    class BenchmarkConfiguration:
        name: str
        module_name: str
        benchmark_class_name: str
        config_class_name: str
        kind: "BenchmarkRunner.BenchmarkKind"
        parameters: Dict[str, Any] = field(default_factory=dict)
        enabled: bool = True

    class Clock(Protocol):
        def now(self) -> datetime: ...

    class _SystemClock:
        def now(self) -> datetime:
            return datetime.now(timezone.utc)

    BASE_DIR = Path(__file__).resolve().parent

    def __init__(
        self,
        clock: "BenchmarkRunner.Clock | None" = None,
        log: Callable[[str], None] | None = None,
    ):
        self.clock = clock or BenchmarkRunner._SystemClock()
        self.log = log or (lambda s: print(s))

    def run_configs_in(self, config_root_directory: str) -> None:
        root_directory = Path(config_root_directory)
        if not root_directory.is_dir():
            raise FileNotFoundError(str(root_directory))

        config_files = sorted(
            [file for file in root_directory.glob("*.json") if file.is_file()]
        )
        processed_model_names: List[str] = []
        results_base_directory: Optional[Path] = None

        for config_file in config_files:
            try:
                self.log(f"\n=== Running benchmarks for config: {config_file.name} ===")
                runtime_environment, benchmark_configs = self._load_configuration(
                    str(config_file)
                )

                if results_base_directory is None:
                    results_base_directory = Path(runtime_environment.results_directory)

                processed_model_names.append(config_file.stem)

                ensure_dir(runtime_environment.results_directory)
                ensure_dir(runtime_environment.outputs_directory)

                current_time_utc = self.clock.now()
                iso_timestamp = current_time_utc.isoformat(timespec="seconds").replace(
                    "+00:00", "Z"
                )
                timestamped_run_name = (
                    current_time_utc.strftime("%Y%m%dT%H%M%SZ") + f"_{config_file.stem}"
                )

                run_output_directory = (
                    Path(runtime_environment.results_directory)
                    / "runs"
                    / timestamped_run_name
                )
                ensure_dir(run_output_directory)

                # Execute benchmarks
                benchmark_results = [
                    self._run_single_benchmark(cfg, runtime_environment)
                    for cfg in benchmark_configs
                ]
                for result in benchmark_results:
                    self.log(
                        f"[{result.get('status', 'unknown')}] {result.get('name', '<unnamed>')}"
                    )

                # Write index
                run_index = {
                    "generated_at": iso_timestamp,
                    "results": benchmark_results,
                }
                write_json(
                    Path(runtime_environment.results_directory) / "index.json",
                    run_index,
                )

                # Move JSON results into the run directory
                for result_file in list(
                    Path(runtime_environment.results_directory).glob("*.json")
                ):
                    destination_file = run_output_directory / result_file.name
                    if destination_file.exists():
                        destination_file.unlink()
                    shutil.move(str(result_file), str(destination_file))

                # Mark the model name (config stem)
                (run_output_directory / "model_name.txt").write_text(
                    config_file.stem, encoding="utf-8"
                )

                # Post-processing / leaderboard for this run
                post_processing_results = auto_run(run_output_directory)
                if post_processing_results.get("csv"):
                    self.log(f"Leaderboard CSV: {post_processing_results['csv']}")

                latest_manifest = {
                    "latest_dir": str(run_output_directory),
                    "generated_at": iso_timestamp,
                    "files": sorted(
                        [p.name for p in run_output_directory.glob("*.json")]
                    ),
                    "csv": post_processing_results.get("csv"),
                    "config": str(config_file),
                }
                write_json(
                    Path(runtime_environment.results_directory) / "latest.json",
                    latest_manifest,
                )

            except Exception as error:
                self.log(f"[error] Failed to run config {config_file.name}: {error}")

        # Build the combined leaderboard across the latest runs of each model
        self._build_combined_leaderboard(results_base_directory, processed_model_names)

    def _load_configuration(self, config_path: str) -> tuple[
        "BenchmarkRunner.RuntimePaths",
        tuple["BenchmarkRunner.BenchmarkConfiguration", ...],
    ]:
        path = Path(config_path)
        if not path.is_absolute():
            path = self.BASE_DIR / path
        if not path.exists():
            raise FileNotFoundError("Create config/benchmarks.json")

        cfg = json.loads(path.read_text(encoding="utf-8"))
        defaults = cfg.get("defaults") or {}

        tasks_dir = rel(self.BASE_DIR, defaults.get("tasks_dir", "tasks"))
        outputs_dir = rel(self.BASE_DIR, defaults.get("output_dir", "outputs/derived"))
        results_dir = rel(self.BASE_DIR, defaults.get("results_dir", "results/derived"))
        runtime = BenchmarkRunner.RuntimePaths(tasks_dir, outputs_dir, results_dir)

        items = cfg.get("benchmarks", [])
        configs: List[BenchmarkRunner.BenchmarkConfiguration] = []
        for item in items:
            kind = BenchmarkRunner.BenchmarkKind(
                str(item.get("kind") or item.get("type"))
            )
            configs.append(
                BenchmarkRunner.BenchmarkConfiguration(
                    name=str(item["name"]),
                    module_name=str(item["module"]),
                    benchmark_class_name=str(
                        item.get("benchmark_class") or item["class"]
                    ),
                    config_class_name=str(item["config_class"]),
                    kind=kind,
                    parameters=dict(item.get("params") or {}),
                    enabled=bool(item.get("enabled", True)),
                )
            )
        return runtime, tuple(configs)

    def _run_single_benchmark(
        self,
        bench_conf: "BenchmarkRunner.BenchmarkConfiguration",
        runtime: "BenchmarkRunner.RuntimePaths",
    ) -> dict:
        record: dict = {"name": bench_conf.name, "module": bench_conf.module_name}
        if not bench_conf.enabled:
            record.update({"status": "skipped", "reason": "disabled in configuration"})
            return record
        try:
            module = importlib.import_module(bench_conf.module_name)
            bench_class = getattr(module, bench_conf.benchmark_class_name)
            cfg_class = getattr(module, bench_conf.config_class_name)

            if not issubclass(bench_class, Benchmark):
                record.update(
                    {
                        "status": "error",
                        "error": f"{bench_conf.benchmark_class_name} is not a Benchmark subclass",
                    }
                )
                return record

            params = dict(bench_conf.parameters)
            if "tasks_file" in params:
                params["tasks_file"] = rel(
                    runtime.tasks_directory, params["tasks_file"]
                )

            cfg = cfg_class(**params)
            bench = bench_class(cfg)
            result = bench.run()

            out_path = runtime.results_directory / f"{bench_conf.name}.json"
            write_json(out_path, result)

            record.update(
                {
                    "status": "success",
                    "result_path": str(out_path),
                    "summary": (
                        f"keys={sorted(result.keys())}"
                        if isinstance(result, dict)
                        else str(type(result))
                    ),
                }
            )
            return record

        except ModuleNotFoundError as e:
            record.update(
                {
                    "status": "skipped",
                    "reason": f"missing dependency: {e.name or str(e)}",
                }
            )
            return record
        except SkipBenchmark as e:
            record.update({"status": "skipped", "reason": str(e)})
            return record
        except Exception as e:
            record.update({"status": "failed", "error": str(e), "trace": exc_str(e)})
            return record

    def _build_combined_leaderboard(
        self, results_base_directory: Optional[Path], processed_model_names: List[str]
    ) -> None:
        try:
            if results_base_directory and processed_model_names:
                runs_parent_directory = results_base_directory / "runs"
                ensure_dir(runs_parent_directory)
                latest_model_run_directories: Dict[str, Path] = {}

                for model_name in processed_model_names:
                    candidate_runs = [
                        run_dir
                        for run_dir in runs_parent_directory.iterdir()
                        if run_dir.is_dir() and run_dir.name.endswith(f"_{model_name}")
                    ]
                    if candidate_runs:
                        latest_model_run_directories[model_name] = max(
                            candidate_runs, key=lambda p: p.name
                        )

                if latest_model_run_directories:
                    current_time_utc = self.clock.now()
                    combined_timestamp = current_time_utc.strftime("%Y%m%dT%H%M%SZ")

                    combined_results_directory = (
                        runs_parent_directory / f"latest_models_{combined_timestamp}"
                    )
                    ensure_dir(combined_results_directory)

                    for (
                        model_name,
                        latest_run_directory,
                    ) in latest_model_run_directories.items():
                        model_combined_directory = (
                            combined_results_directory / model_name
                        )
                        ensure_dir(model_combined_directory)

                        try:
                            (model_combined_directory / "model_name.txt").write_text(
                                model_name, encoding="utf-8"
                            )
                        except Exception:
                            pass

                        for json_file in latest_run_directory.glob("*.json"):
                            try:
                                shutil.move(
                                    str(json_file),
                                    str(model_combined_directory / json_file.name),
                                )
                            except Exception as move_error:
                                self.log(
                                    f"[warn] move failed for {json_file}: {move_error}"
                                )

                        # Clean up old run directory
                        shutil.rmtree(latest_run_directory, ignore_errors=True)

                    combined_processing_results = auto_run(combined_results_directory)
                    if combined_processing_results.get("csv"):
                        self.log(
                            f"\nCombined leaderboard CSV (latest per model): {combined_processing_results['csv']}"
                        )

                    combined_manifest = {
                        "combined_dir": str(combined_results_directory),
                        "csv": combined_processing_results.get("csv"),
                        "models": sorted(list(latest_model_run_directories.keys())),
                    }
                    write_json(
                        results_base_directory / "latest_models.json", combined_manifest
                    )

                    overall_latest_manifest = {
                        "latest_dir": str(combined_results_directory),
                        "generated_at": current_time_utc.isoformat(
                            timespec="seconds"
                        ).replace("+00:00", "Z"),
                        "files": sorted(
                            [
                                p.name
                                for p in combined_results_directory.glob("**/*.json")
                            ]
                        ),
                        "csv": combined_processing_results.get("csv"),
                    }
                    write_json(
                        results_base_directory / "latest.json", overall_latest_manifest
                    )

        except Exception as error:
            self.log(f"[warn] Failed to build combined leaderboard: {error}")


def run(config_root_directory: str) -> None:
    BenchmarkRunner().run_configs_in(config_root_directory)
