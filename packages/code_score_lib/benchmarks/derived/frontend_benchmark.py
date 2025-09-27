from pathlib import Path

from pydantic import Field

from ..base.dspy_benchmark import DspyBenchmark, DspyConfig


class FrontendConfig(DspyConfig):
    tasks_file: Path = Field(
        ..., description="Path to the JSON file that defines benchmark tasks"
    )


class FrontendBenchmark(DspyBenchmark):
    """DSPy benchmark for evaluating React component generation."""

    def __init__(self, cfg: FrontendConfig) -> None:
        super().__init__(cfg, cfg.tasks_file)
