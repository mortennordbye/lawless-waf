"""Read a WAF exclusions file from a local path — optionally at a git ref — instead of pasting.

The operator points the app at a file inside a directory mounted into the container (typically
their infra repo; see ``EXCLUSIONS_ROOT`` in ``.env.example`` and the read-only mount in
``compose.yaml``). Two modes, both fully local (no network, no credentials):

* no ``ref`` — read the file as it is on disk right now (the working tree). "Get the latest" is
  just re-reading it.
* a ``ref`` (branch / tag / commit) — read the file at that ref with ``git show <ref>:<path>``,
  without touching the working tree, so you can check ``main`` while on a feature branch.

Security (this runs on localhost, but the path still crosses a trust boundary):

* Every read is confined to ``settings.exclusions_root``. The resolved real path must stay inside
  the resolved real root — symlinks and ``..`` that escape are rejected.
* Only regular files, capped at ``MAX_TF_CONTENT`` bytes.
* ``git`` is invoked as an argv list (never a shell string); ``ref`` is validated against a safe
  charset and may not start with ``-`` (no option injection). ``-c safe.directory=*`` avoids
  git's "dubious ownership" refusal on a repo owned by another uid on the host mount.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from .models import MAX_TF_CONTENT
from .settings import Settings

SOURCE_FILENAME = "exclusions-source.json"

# A git ref: branch/tag/commit. Refs allow / . - _ and alphanumerics and must not start with '-'
# (so it can't be read as a git option). The charset alone can't exclude '..' (a ref-range), so
# :func:`_valid_ref` also rejects any ref containing '..'.
REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
_REF_RE = re.compile(REF_PATTERN)


def _valid_ref(ref: str) -> bool:
    return bool(_REF_RE.match(ref)) and ".." not in ref


class LocalExclusionsError(RuntimeError):
    """A local exclusions read failed; ``str(self)`` is a safe, user-facing reason."""


class ExclusionsSource(BaseModel):
    """Operator-configured pointer to a local exclusions file (persisted in DATA_DIR)."""

    # Path to the file, relative to exclusions_root (an absolute path is also accepted as long as
    # it resolves inside the root).
    path: str = Field(default="", max_length=1000)
    # Optional git branch / tag / commit to read the file at; empty = the working-tree file.
    ref: str = Field(default="", max_length=200)


def load_source(settings: Settings) -> ExclusionsSource:
    """The persisted exclusions-file pointer (empty if never set)."""
    p = settings.data_dir / SOURCE_FILENAME
    if p.is_file():
        try:
            return ExclusionsSource.model_validate_json(p.read_text())
        except (OSError, ValueError):
            pass
    return ExclusionsSource()


def save_source(settings: Settings, source: ExclusionsSource) -> ExclusionsSource:
    p = settings.data_dir / SOURCE_FILENAME
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(source.model_dump(), indent=2))
    return source


def _resolve_in_root(settings: Settings, rel_path: str) -> Path:
    root = settings.exclusions_root_path
    if root is None:
        raise LocalExclusionsError(
            "local exclusions are not configured — set EXCLUSIONS_ROOT and mount the directory "
            "(see compose.yaml / .env.example)."
        )
    if not rel_path.strip():
        raise LocalExclusionsError("no exclusions file path is set.")
    root = root.resolve()
    candidate = (root / rel_path).resolve() if not Path(rel_path).is_absolute() else Path(rel_path).resolve()
    if root != candidate and root not in candidate.parents:
        raise LocalExclusionsError("path is outside the allowed exclusions directory.")
    return candidate


def _read_working_tree(path: Path) -> str:
    if not path.is_file():
        raise LocalExclusionsError(f"file not found: {path.name}")
    if path.stat().st_size > MAX_TF_CONTENT:
        raise LocalExclusionsError(f"file too large (> {MAX_TF_CONTENT} bytes).")
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise LocalExclusionsError(f"could not read file: {e}") from e


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    # -c safe.directory=* so a repo owned by a different uid on the host mount isn't refused.
    argv = ["git", "-c", "safe.directory=*", *args]  # git resolved from PATH; fixed args, no shell
    return subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=15)  # noqa: S603


def _read_at_ref(path: Path, ref: str) -> tuple[str, str]:
    """Return ``(content, resolved_commit)`` for ``path`` at git ``ref`` in its repo."""
    if not _valid_ref(ref):
        raise LocalExclusionsError("invalid git ref.")
    repo_dir = path.parent
    try:
        top = _git(["rev-parse", "--show-toplevel"], repo_dir)
    except FileNotFoundError as e:
        raise LocalExclusionsError("git is not available in this environment.") from e
    except subprocess.TimeoutExpired as e:
        raise LocalExclusionsError("git timed out.") from e
    if top.returncode != 0:
        raise LocalExclusionsError("the file is not inside a git repository (a ref needs one).")
    toplevel = Path(top.stdout.strip())
    try:
        rel = path.relative_to(toplevel)
    except ValueError as e:
        raise LocalExclusionsError("could not locate the file within its git repository.") from e

    commit = _git(["rev-parse", "--short", ref], toplevel)
    if commit.returncode != 0:
        raise LocalExclusionsError(f"unknown git ref {ref!r}.")
    show = _git(["show", f"{ref}:{rel.as_posix()}"], toplevel)
    if show.returncode != 0:
        raise LocalExclusionsError(f"{rel.as_posix()!r} does not exist at ref {ref!r}.")
    if len(show.stdout.encode("utf-8")) > MAX_TF_CONTENT:
        raise LocalExclusionsError(f"file too large (> {MAX_TF_CONTENT} bytes).")
    return show.stdout, commit.stdout.strip()


def read_exclusions(settings: Settings, path: str, ref: str = "") -> dict:
    """Read the exclusions file at ``path`` (relative to the root), optionally at git ``ref``.

    Returns ``{content, path, ref, resolved_commit, from_git}``. Raises
    :class:`LocalExclusionsError` with a safe message on any problem.
    """
    resolved = _resolve_in_root(settings, path)
    ref = (ref or "").strip()
    if ref:
        content, commit = _read_at_ref(resolved, ref)
        return {"content": content, "path": path, "ref": ref, "resolved_commit": commit, "from_git": True}
    return {
        "content": _read_working_tree(resolved),
        "path": path,
        "ref": "",
        "resolved_commit": None,
        "from_git": False,
    }
