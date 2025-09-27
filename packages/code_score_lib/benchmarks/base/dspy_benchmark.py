import json
from pathlib import Path
from typing import Optional, Union, cast

from pydantic import BaseModel, Field, ValidationError
import dspy

from .benchmark import Benchmark, BenchmarkConfig

JsonValue = Union[
    str,
    int,
    float,
    bool,
    None,
    dict[str, "JsonValue"],
    list["JsonValue"],
]
JsonDict = dict[str, JsonValue]


class DspyConfig(BenchmarkConfig):
    """Configuration for DSPy-based benchmarks."""

    name: str
    output_dir: Path
    env: dict[str, str]
    parse_json_outputs: bool = True
    stop_on_error: bool = False
    print_commands: bool = True
    judge_llm_base_url: str
    judge_llm_api_key: str
    judge_llm_model: str
    subject_llm_base_url: str
    subject_llm_api_key: str
    subject_llm_model: str


class Task(BaseModel):
    """Representation of a benchmark task loaded from JSON."""

    name: str
    description: str
    input_scaffold: str
    evaluation_prompt: str

    def to_dict(self) -> dict[str, str]:
        return cast(dict[str, str], self.model_dump())


class DspyBenchmark(Benchmark):
    """Base class for benchmarks that load tasks from JSON and use DSPy."""

    def __init__(self, cfg: DspyConfig, tasks_file: Path) -> None:
        super().__init__(cfg)
        self.cfg = cfg
        self.tasks_file = Path(tasks_file)
        self.tasks: list[Task] = self._load_tasks(self.tasks_file)
        self._judge_llm_params = self._extract_llm_params("judge")
        self._subject_llm_params = self._extract_llm_params("subject")

    def prepare(self) -> list[dict[str, str]]:
        """Return the list of tasks as dictionaries."""
        return [task.to_dict() for task in self.tasks]

    def evaluate_task(self, task: Task, candidate_code: str) -> Optional[JsonDict]:
        """Evaluate a candidate solution using LLM as judge."""

        class CodeJudgeSignature(dspy.Signature):
            description = dspy.InputField(desc="Brief description of the task")
            candidate_code = dspy.InputField(
                desc="Candidate solution code to be evaluated"
            )
            rubric = dspy.InputField(desc="Evaluation rubric/instructions")
            result_json: str = dspy.OutputField(desc="JSON-encoded evaluation scores")

        with dspy.context(lm=dspy.LM(**self._judge_llm_params)):
            judge = dspy.ChainOfThought(CodeJudgeSignature)

            rubric = (
                task.evaluation_prompt
                + "\nReturn your assessment as a JSON object with keys for each criterion "
                + "(e.g. functionality, code_quality, performance, accessibility, error_handling) and "
                + "values as integers between 0 and 10. Include a brief justification for each score "
                + "under a 'justification' field."
            )
            prediction = judge(
                description=task.description,
                candidate_code=candidate_code,
                rubric=rubric,
            )

        try:
            parsed: JsonValue = json.loads(prediction.result_json)
        except json.JSONDecodeError:
            return {"raw": prediction.result_json}

        if isinstance(parsed, dict):
            return cast(JsonDict, parsed)
        return {"raw": prediction.result_json}

    def generate_solution(self, task: Task) -> str:
        """Generate a candidate solution for a given task using DSPy."""

        class CodeGenSignature(dspy.Signature):
            instruction = dspy.InputField(desc="Description of the desired code")
            scaffold = dspy.InputField(desc="Starter code or hints")
            code = dspy.OutputField(desc="Generated code fulfilling the instruction")

        with dspy.context(lm=dspy.LM(**self._subject_llm_params)):
            generator = dspy.ChainOfThought(CodeGenSignature)

            instruction = (
                "Write a complete solution in the appropriate programming language for the "
                f"following task: {task.description}. Use the scaffold if provided."
            )
            result = generator(instruction=instruction, scaffold=task.input_scaffold)
        return getattr(result, "code", "")

    def run(self) -> list[JsonDict]:
        """Execute the benchmark end-to-end."""
        results: list[JsonDict] = []
        for task in self.tasks:
            candidate_code = self.generate_solution(task)
            evaluation = self.evaluate_task(task, candidate_code)
            results.append(
                {
                    "task_name": task.name,
                    "candidate_code": candidate_code,
                    "evaluation": evaluation,
                }
            )
        return results

    def _load_tasks(self, path: Path) -> list[Task]:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        tasks: list[Task] = []
        for index, item in enumerate(data):
            try:
                task = Task.model_validate(item)
                tasks.append(task)
            except ValidationError as exc:
                raise ValueError(f"Invalid task entry at index {index}") from exc
        return tasks

    def _extract_llm_params(self, prefix: str) -> Optional[dict[str, str]]:
        model = getattr(self.cfg, f"{prefix}_llm_model", "")
        api_base = getattr(self.cfg, f"{prefix}_llm_base_url", "")
        api_key = getattr(self.cfg, f"{prefix}_llm_api_key", "")
        if not all([model, api_base, api_key]) or dspy is None:
            return None
        return {"model": model, "api_base": api_base, "api_key": api_key}
