from pathlib import Path

from pydantic import Field

from ..base.dspy_benchmark import DspyBenchmark, DspyConfig


class UnitTestConfig(DspyConfig):
    tasks_file: Path = Field(
        ..., description="Path to the JSON file that defines benchmark tasks"
    )


class UnitTestBenchmark(DspyBenchmark):
    """DSPy benchmark for unit test generation."""

    def __init__(self, cfg: UnitTestConfig) -> None:
        super().__init__(cfg, cfg.tasks_file)
