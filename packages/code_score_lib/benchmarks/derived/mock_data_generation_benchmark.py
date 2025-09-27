from pathlib import Path

from pydantic import Field

from ..base.dspy_benchmark import DspyBenchmark, DspyConfig


from ..base.dspy_benchmark import DspyBenchmark, DspyConfig


class MockDataConfig(DspyConfig):
    tasks_file: Path = Field(
        ..., description="Path to the JSON file that defines benchmark tasks"
    )


class MockDataGenerationBenchmark(DspyBenchmark):
    """DSPy benchmark for synthetic mock data generation."""

    def __init__(self, cfg: MockDataConfig) -> None:
        super().__init__(cfg, cfg.tasks_file)
