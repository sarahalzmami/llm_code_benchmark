import json
from pathlib import Path
from typing import Any, Dict


def exc_str(e: BaseException) -> str:
    """
    Convert an exception and its traceback into a single formatted string.

    Args:
        e (BaseException): The exception instance to format.

    Returns:
        str: The full traceback as a single string.

    Example:
        try:
            1 / 0
        except Exception as exc:
            print(_exc_str(exc))
    """
    import traceback as tb

    return "".join(tb.format_exception(type(e), e, e.__traceback__))


def ensure_dir(path: Path) -> None:
    """
    Ensure that a directory exists at the given path.

    Creates the directory and all intermediate directories if they do not exist.
    If the directory already exists, no error is raised.

    Args:
        p (Path): The directory path to create.

    Example:
        ensure_dir(Path("logs"))
    """
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: Any) -> Path:
    """
    Write a Python object as formatted JSON to a file.

    Ensures the parent directory exists before writing.
    Objects that are not JSON serializable are converted to strings.

    Args:
        path (Path): The file path where the JSON will be written.
        obj (Any): The Python object to serialize to JSON.

    Returns:
        Path: The path to the written JSON file.

    Example:
        data = {"name": "Alice", "age": 30}
        _write_json(Path("output/data.json"), data)
    """
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    return path


def rel(base: Path, value: str | Path) -> Path:
    """
    Resolve a relative or absolute path against a base directory.

    If the value is already absolute, it is returned unchanged.
    Otherwise, it is appended to the base path.

    Args:
        base (Path): The base directory.
        value (str | Path): The relative or absolute path to resolve.

    Returns:
        Path: The resolved path.

    Example:
        base = Path("/home/user")
        print(_rel(base, "docs/file.txt"))  # -> /home/user/docs/file.txt
    """
    p = Path(value)
    return p if p.is_absolute() else (base / p)
