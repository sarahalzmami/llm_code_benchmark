from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import Field

from ..base.benchmark import Benchmark, BenchmarkConfig
from ..base.command_runner_mixin import CommandRunnerMixin


class BaxBenchConfig(BenchmarkConfig):
    """Configuration for running BaxBench via its CLI.

    Notes
    - This wrapper shells into the BaxBench repo directory and runs its CLI
      (src/main.py) using either pipenv or the system python.
    - Because the common command runner currently doesn't apply cwd/env to
      subprocess.run, we construct a single bash command string that `cd`s into
      the repo and runs the CLI in one shot.
    """

    # Path to the BaxBench repository root (containing src/)
    bench_repo_dir: Path

    # Phases to execute
    # When run_all is True, the benchmark will run all three phases in order:
    # generate -> test -> evaluate, regardless of the individual toggles.
    run_all: bool = True
    run_generate: bool = True
    run_test: bool = True
    run_evaluate: bool = True

    # Execution method
    use_pipenv: bool = True  # if True: `pipenv run python`, else: `python`

    # CLI core params
    models: List[str] = Field(default_factory=list)
    mode: str = "generate"  # not used directly if running multiple phases
    n_samples: int = 1
    temperature: float = 0.4
    reasoning_effort: str = "high"  # low | medium | high
    spec_type: str = "openapi"  # openapi | text
    safety_prompt: str = "none"  # none | generic | specific

    # Selection
    scenarios: Optional[List[str]] = None
    exclude_scenarios: Optional[List[str]] = None
    envs: Optional[List[str]] = None
    exclude_envs: Optional[List[str]] = None
    only_samples: Optional[List[int]] = None
    ks: Optional[List[int]] = None

    # Runtime & backoff
    timeout: int = 300
    num_ports: int = 10000
    min_port: int = 12345
    max_concurrent_runs: Optional[int] = None
    max_retries: int = 20
    base_delay: float = 1.0
    max_delay: float = 128.0

    # Toggles
    force: bool = False
    skip_failed: bool = False
    prune_docker: bool = False
    openrouter: bool = False
    vllm: bool = False
    vllm_port: int = 8000

    # Where BaxBench writes its results. If not provided, uses this benchmark's
    # output_dir. Supports a couple of simple templates when provided as string:
    #  - "$(date +%s)": replaced with current epoch seconds
    #  - "{timestamp}":  replaced with current epoch seconds
    results_dir_override: Optional[Path] = None


class BaxBenchBenchmark(CommandRunnerMixin, Benchmark):
    def __init__(self, cfg: BaxBenchConfig) -> None:
        super().__init__(cfg)
        self.cfg: BaxBenchConfig

    def _bash_cd_and_run(self, inner_cmd: str) -> Tuple[List[str], Dict[str, Any]]:
        """Build a bash command that cds into the repo and runs `inner_cmd`.

        The environment key/values in cfg.env are inlined as `VAR=value` prefixes
        to the command to avoid relying on subprocess env handling.
        """
        repo = str(self.cfg.bench_repo_dir)

        # Inline env as `KEY=VAL` prefixes so they apply to the process.
        env_prefix = " ".join(
            f"{k}={shlex.quote(str(v))}" for k, v in (self.cfg.env or {}).items()
        )
        env_prefix = (env_prefix + " ") if env_prefix else ""

        cmd_str = f"cd {shlex.quote(repo)} && {env_prefix}{inner_cmd}"
        return ["bash", "-lc", cmd_str], {"key": None, "expects_json_at": None}

    def _cli_prefix(self) -> str:
        if self.cfg.use_pipenv:
            return "pipenv run python src/main.py"
        return "python src/main.py"

    @staticmethod
    def _expand_results_dir(value: str) -> str:
        """Lightweight expansion for timestamp placeholders.

        - Replaces occurrences of '$(date +%s)' with current epoch seconds
        - Replaces occurrences of '{timestamp}' with current epoch seconds
        """
        import time

        ts = str(int(time.time()))
        if "$(date +%s)" in value:
            value = value.replace("$(date +%s)", ts)
        if "{timestamp}" in value:
            value = value.replace("{timestamp}", ts)
        return value

    def _common_flags(self) -> List[str]:
        flags: List[str] = []

        def add(flag: str, value: Any) -> None:
            flags.extend([flag, str(value)])

        # Required list: models
        if not self.cfg.models:
            raise ValueError("BaxBenchConfig.models must not be empty")
        flags.append("--models")
        flags.extend(shlex.quote(m) for m in self.cfg.models)

        # Optional lists
        if self.cfg.envs:
            flags.append("--envs")
            flags.extend(shlex.quote(e) for e in self.cfg.envs)
        if self.cfg.exclude_envs:
            flags.append("--exclude_envs")
            flags.extend(shlex.quote(e) for e in self.cfg.exclude_envs)
        if self.cfg.scenarios:
            flags.append("--scenarios")
            flags.extend(shlex.quote(s) for s in self.cfg.scenarios)
        if self.cfg.exclude_scenarios:
            flags.append("--exclude_scenarios")
            flags.extend(shlex.quote(s) for s in self.cfg.exclude_scenarios)
        if self.cfg.only_samples:
            flags.append("--only_samples")
            flags.extend(str(i) for i in self.cfg.only_samples)
        if self.cfg.ks:
            flags.append("--ks")
            flags.extend(str(k) for k in self.cfg.ks)

        # Simple scalars
        add("--n_samples", self.cfg.n_samples)
        add("--temperature", self.cfg.temperature)
        add("--reasoning_effort", self.cfg.reasoning_effort)
        add("--spec_type", self.cfg.spec_type)
        add("--safety_prompt", self.cfg.safety_prompt)

        # Output directory for BaxBench results
        results_dir_input = self.cfg.results_dir_override or self.cfg.output_dir
        # Use repo-relative value if given as relative path. Expansion is on the
        # raw string before passing into the shell command.
        results_dir_str = self._expand_results_dir(str(results_dir_input))
        add("--results_dir", results_dir_str)

        # Runtime / backoff
        if self.cfg.max_concurrent_runs is not None:
            add("--max_concurrent_runs", self.cfg.max_concurrent_runs)
        add("--timeout", self.cfg.timeout)
        add("--num_ports", self.cfg.num_ports)
        add("--min_port", self.cfg.min_port)
        add("--max_retries", self.cfg.max_retries)
        add("--base_delay", self.cfg.base_delay)
        add("--max_delay", self.cfg.max_delay)

        # Boolean toggles
        if self.cfg.force:
            flags.append("--force")
        if self.cfg.skip_failed:
            flags.append("--skip_failed")
        if self.cfg.prune_docker:
            flags.append("--prune_docker")
        if self.cfg.openrouter:
            flags.append("--openrouter")
        if self.cfg.vllm:
            flags.append("--vllm")
            add("--vllm_port", self.cfg.vllm_port)

        return flags

    def _assemble(self, mode: str) -> Tuple[List[str], Dict[str, Any]]:
        prefix = self._cli_prefix()
        flags = ["--mode", shlex.quote(mode), *self._common_flags()]
        # Compose final command string with proper spacing
        inner = " ".join([prefix, *flags])
        cmd, meta = self._bash_cd_and_run(inner)
        meta["key"] = f"bax::{mode}"
        return cmd, meta

    def prepare(self) -> List[Tuple[List[str], Dict[str, Any]]]:
        items: List[Tuple[List[str], Dict[str, Any]]] = []
        if self.cfg.run_all:
            # Standard BaxBench sequence
            items.append(self._assemble("generate"))
            items.append(self._assemble("test"))
            items.append(self._assemble("evaluate"))
        else:
            if self.cfg.run_generate:
                items.append(self._assemble("generate"))
            if self.cfg.run_test:
                items.append(self._assemble("test"))
            if self.cfg.run_evaluate:
                items.append(self._assemble("evaluate"))
            # If none selected, fall back to single-mode from cfg.mode
            if not items:
                items.append(self._assemble(self.cfg.mode))
        return items

    def run(self) -> Dict[str, Any]:
        items = self.prepare()
        raw = self._run_commands(
            items,
            parse_json_outputs=False,
            stop_on_error=self.cfg.stop_on_error,
            print_commands=self.cfg.print_commands,
            base_env=None,  # env is inlined in the bash command string
        )

        # Return a concise summary with pointers to where results are written
        results_dir = str(self.cfg.results_dir_override or self.cfg.output_dir)
        return {
            "results_dir": results_dir,
            "repo_dir": str(self.cfg.bench_repo_dir),
            "steps": {k: {**v} for k, v in raw.items()},
        }
