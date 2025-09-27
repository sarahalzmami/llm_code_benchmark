import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple


class CommandRunnerMixin:
    """Helper mixin to build and run external commands.

    Subclasses typically use `_build_command` to create a list of
    `(argv, meta)` tuples and then pass those to `_run_commands`. The
    runner merges `env`, executes each command, and—if configured—parses
    JSON outputs written to disk by the command.
    """

    @staticmethod
    def _format_flag(name: str, style: str = "dash") -> str:
        """Return a CLI flag string for a given option name.

        Parameters
        - name: The option name without leading dashes (e.g. "batch_size").
        - style: Flag formatting style:
          - "dash": convert underscores to dashes ("batch_size" -> "--batch-size").
          - "underscore": preserve underscores ("batch_size" -> "--batch_size").
          - "preserve": use as provided; prepend "--" if missing.

        Returns
        - The formatted flag suitable for inclusion in an argv list.
        """
        if style == "dash":
            return f"--{name.replace('_', '-')}"
        if style == "underscore":
            return f"--{name}"
        if style == "preserve":
            prefix = "--" if not name.startswith("--") else ""
            return f"{prefix}{name}"
        raise ValueError(f"Unknown flag style: {style}")

    @classmethod
    def _build_command(
        cls,
        *,
        executable: str,
        positional: Optional[List[str]] = None,
        flags: Optional[Mapping[str, Any]] = None,
        multi_flags: Optional[Mapping[str, Iterable[Any]]] = None,
        repeat_flags: Optional[Mapping[str, Iterable[Any]]] = None,
        free_kv: Optional[List[Tuple[str, Any]]] = None,
        cwd: Optional[str | Path] = None,
        env: Optional[Mapping[str, str]] = None,
        key: Optional[str] = None,
        expects_json_at: Optional[str | Path] = None,
        flag_style: str = "dash",  # 'dash' | 'underscore' | 'preserve'
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Construct an argv list plus execution metadata.

        Parameters
        - executable: Program to execute (e.g. "python").
        - positional: Positional arguments to append after the executable.
        - flags: Mapping of single‑value flags; booleans add the flag when True.
        - multi_flags: Flags that take a list of values (one flag followed by N values).
        - repeat_flags: Flags that are repeated once per value (flag value flag value ...).
        - free_kv: Freeform key/value pairs appended verbatim.
        - cwd: Working directory to run in.
        - env: Environment variables to merge with process env.
        - key: Logical identifier for this command in result dicts.
        - expects_json_at: Path of a JSON file the command is expected to write.
        - flag_style: Controls formatting of flag names (see `_format_flag`).

        Returns
        - (argv, meta) where `argv` is a list of strings and `meta` contains
          normalized fields: `cwd`, `env`, `key`, `expects_json_at`.
        """
        cmd: List[str] = [executable]

        if positional:
            cmd.extend(str(p) for p in positional)

        if flags:
            for k, v in flags.items():
                if v is None:
                    continue
                flag = cls._format_flag(k, style=flag_style)
                if isinstance(v, bool):
                    if v:
                        cmd.append(flag)
                else:
                    cmd += [flag, str(v)]

        if multi_flags:
            for k, values in multi_flags.items():
                if values is None:
                    continue
                flag = cls._format_flag(k, style=flag_style)
                vals = [str(x) for x in values]
                if vals:
                    cmd += [flag, *vals]

        if repeat_flags:
            for k, values in repeat_flags.items():
                if values is None:
                    continue
                flag = cls._format_flag(k, style=flag_style)
                for v in values:
                    cmd += [flag, str(v)]

        if free_kv:
            for k, v in free_kv:
                cmd += [str(k), str(v)]

        meta: Dict[str, Any] = {
            "cwd": str(cwd) if cwd is not None else None,
            "env": dict(env) if env is not None else None,
            "key": key,
            "expects_json_at": Path(expects_json_at) if expects_json_at else None,
        }

        return cmd, meta

    @staticmethod
    def _run_commands(
        items: Iterable[Tuple[List[str], Dict[str, Any]]],
        *,
        parse_json_outputs: bool = True,
        stop_on_error: bool = False,
        print_commands: bool = True,
        base_env: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, dict]:
        """Execute a sequence of commands and collect results.

        Behavior
        - Prints each command (argv joined with safe quoting) when `print_commands` is True.
        - Merges `base_env` with any per‑command `env` before execution.
        - Runs each command with `subprocess.run(..., check=True)`; on failure,
          either raises (when `stop_on_error=True`) or continues to the next.
        - If `parse_json_outputs` and `expects_json_at` is provided and exists,
          attempts to parse that file and uses the resulting object as the
          value for the command's key in the returned dict. Otherwise an empty
          dict is stored for that key.
        Returns
        - Mapping from a per‑command `key` (explicit or inferred) to parsed
          JSON data (or `{}` when none is parsed).
        """
        results: Dict[str, dict] = {}

        if base_env is None:
            base_env = os.environ

        for idx, (cmd, meta) in enumerate(items):
            if print_commands:
                print("Executing:", " ".join(shlex.quote(c) for c in cmd))

            merged_env: MutableMapping[str, str] = dict(base_env)
            if meta.get("env"):
                merged_env.update({k: str(v) for k, v in meta["env"].items()})

            try:
                subprocess.run(
                    cmd,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                if stop_on_error:
                    raise RuntimeError(f"Command failed: {exc}") from exc
                print(f"Command failed (continuing): {exc}")
                continue

            key = meta.get("key")
            json_path: Optional[Path] = meta.get("expects_json_at")

            if parse_json_outputs and json_path:
                if json_path.exists():
                    try:
                        with open(json_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                    except json.JSONDecodeError:
                        print(f"Warning: could not parse JSON from {json_path}.")
                        data = {}
                else:
                    print(f"Warning: expected results file {json_path} not found.")
                    data = {}
            else:
                data = {}

            if not key:
                if json_path:
                    key = json_path.stem
                elif len(cmd) > 1:
                    key = cmd[1]
                else:
                    key = f"cmd_{idx}"

            results[str(key)] = data

        return results
