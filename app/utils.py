from pathlib import Path


def rel(value: str | Path) -> Path:
    """Resolve a path relative to this package directory.

    - If ``value`` is absolute, it is returned unchanged.
    - If ``value`` is relative, it is resolved against the directory
      containing this file (``benchmark_app``).

    Args:
        value: Relative or absolute path-like value.

    Returns:
        A normalized, absolute ``Path``.

    Example:
        >>> rel("static")  # resolves to benchmark_app/static
        PosixPath(".../benchmark_app/static")
    """
    base = Path(__file__).resolve().parent
    p = Path(value)
    return p if p.is_absolute() else (base / p).resolve()
