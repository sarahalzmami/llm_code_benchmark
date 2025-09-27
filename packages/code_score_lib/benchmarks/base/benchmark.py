from abc import ABC, abstractmethod
from typing import Any
from pathlib import Path
from pydantic import BaseModel


class BenchmarkConfig(BaseModel):
    name: str
    output_dir: Path
    env: dict
    parse_json_outputs: bool = True
    stop_on_error: bool = False
    print_commands: bool = True


class Benchmark(ABC):
    def __init__(self, cfg: BenchmarkConfig) -> None:
        self.cfg = cfg
        self.cfg.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def prepare(self) -> Any:
        """Return whatever your run() needs. For command-based flows, this can be
        a list of (cmd, meta). For in-process flows, return your own structure."""

    def postprocess(self, raw: Any) -> Any:
        return raw

    def run(self) -> Any:
        """Default: just prepare and return. Subclasses commonly override run() to
        call helper utilities or do custom logic, then postprocess()."""
        prepared = self.prepare()
        return self.postprocess(prepared)
