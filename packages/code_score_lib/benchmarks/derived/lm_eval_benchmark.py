import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..base.benchmark import BenchmarkConfig, Benchmark
from ..base.command_runner_mixin import CommandRunnerMixin


class LmEvalConfig(BenchmarkConfig):
    served_model: str = ""
    tasks: List[str]
    base_url: str
    api_key: str
    model_type: str = "local-completions"
    batch_size: int
    model_args: Dict[str, Any]
    apply_chat_template: bool = False
    limit: Optional[int] = None


class LmEvalBenchmark(CommandRunnerMixin, Benchmark):
    def __init__(self, cfg: LmEvalConfig) -> None:
        super().__init__(cfg)
        self.cfg: LmEvalConfig

    def prepare(self) -> List[Tuple[List[str], Dict[str, Any]]]:

        os.environ["HF_ALLOW_CODE_EVAL"] = "1"
        items: List[Tuple[List[str], Dict[str, Any]]] = []
        out_dir = self.cfg.output_dir

        name = self.cfg.served_model
        result_json = out_dir / f"{name.replace('/', '_')}.json"
        args = {
            "model": name,
            "base_url": self.cfg.base_url,
            "api_key": self.cfg.api_key,
        }
        args.update(self.cfg.model_args)
        args_str = ",".join(f"{k}={v}" for k, v in args.items())

        flags = {
            "model": self.cfg.model_type,
            "model_args": args_str,
            "tasks": ",".join(self.cfg.tasks),
            "batch_size": self.cfg.batch_size,
            "confirm_run_unsafe_code": True,
            "output_path": str(result_json),
            "apply_chat_template": self.cfg.apply_chat_template,
            "limit": self.cfg.limit,
        }

        items.append(
            self._build_command(
                executable="lm_eval",
                flags=flags,
                expects_json_at=result_json,
                key=name,
                flag_style="underscore",  # lm_eval requires underscores
                env=None,
            )
        )
        return items

    def postprocess(
        self,
    ) -> dict:
        output_dir = Path(self.cfg.output_dir)

        # find all json files in the directory
        json_files = list(output_dir.glob("*.json"))
        if not json_files:
            raise FileNotFoundError(f"No JSON files found in {output_dir}")

        # pick the latest file based on modification time
        latest_file = max(json_files, key=lambda f: f.stat().st_mtime)

        with open(latest_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data

    def run(self) -> Dict[str, Any]:
        items = self.prepare()
        raw = self._run_commands(
            items,
            parse_json_outputs=self.cfg.parse_json_outputs,
            stop_on_error=self.cfg.stop_on_error,
            print_commands=self.cfg.print_commands,
            base_env={**os.environ, **self.cfg.env},
        )
        return self.postprocess()
