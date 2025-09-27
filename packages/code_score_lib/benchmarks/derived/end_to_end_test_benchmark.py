from pathlib import Path

from pydantic import Field

from ..base.dspy_benchmark import DspyBenchmark, DspyConfig


class EndToEndConfig(DspyConfig):
    tasks_file: Path = Field(
        description="Path to the JSON file that defines benchmark tasks"
    )


class EndToEndTestBenchmark(DspyBenchmark):
    """DSPy benchmark for end-to-end test generation."""

    def __init__(self, cfg: EndToEndConfig) -> None:
        super().__init__(cfg, cfg.tasks_file)
