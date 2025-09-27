from pathlib import Path

from pydantic import Field

from ..base.dspy_benchmark import DspyBenchmark, DspyConfig


class IntegrationConfig(DspyConfig):
    tasks_file: Path = Field(
        ..., description="Path to the JSON file that defines benchmark tasks"
    )


class IntegrationTestBenchmark(DspyBenchmark):
    """DSPy benchmark for integration test generation."""

    def __init__(self, cfg: IntegrationConfig) -> None:
        super().__init__(cfg, cfg.tasks_file)
