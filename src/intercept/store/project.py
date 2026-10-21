"""Project files.

A project is a directory that holds everything an engagement produced: the
traffic history, the scope rules, the notes, the issues and the reports. The
daemon keeps a registry of the projects it knows about so the desktop shell can
list, open and save them.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

__all__ = ["ProjectStore"]

_VERSION = 1


class ProjectStore:
    """The registry of projects and the code that saves and loads them."""

    def __init__(self, home: Path | str) -> None:
        self.home = Path(home)
        self.projects_root = self.home / "projects"
        self.projects_root.mkdir(parents=True, exist_ok=True)
        self._registry_path = self.home / "projects.json"
        self._current: str | None = None

    # -------------------------------------------------------------- registry

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self._registry_path.read_text())
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("projects", [])
        data.setdefault("current", None)
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self._registry_path.write_text(json.dumps(data, indent=2))

    def list(self) -> list[dict[str, Any]]:
        data = self._read()
        projects = data.get("projects", [])
        for project in projects:
            project["current"] = project.get("id") == data.get("current")
        return projects

    def current(self) -> dict[str, Any] | None:
        data = self._read()
        current = data.get("current")
        if not current:
            return None
        for project in data.get("projects", []):
            if project.get("id") == current:
                project["current"] = True
                return project
        return None

    def get(self, project_id: str) -> dict[str, Any] | None:
        for project in self.list():
            if project.get("id") == project_id:
                return project
        return None

    # --------------------------------------------------------------- create

    def create(
        self,
        name: str,
        *,
        path: Path | str | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        import uuid

        project_id = uuid.uuid4().hex[:8]
        directory = Path(path) if path else self.projects_root / _slug(name)
        directory.mkdir(parents=True, exist_ok=True)
        project = {
            "id": project_id,
            "name": name,
            "description": description,
            "path": str(directory),
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        (directory / "project.json").write_text(
            json.dumps({**project, "version": _VERSION}, indent=2)
        )
        data = self._read()
        data["projects"] = [p for p in data["projects"] if p.get("id") != project_id]
        data["projects"].append(project)
        data["current"] = project_id
        self._write(data)
        self._current = project_id
        return project

    def open(self, project_id: str) -> dict[str, Any] | None:
        project = self.get(project_id)
        if project is None:
            return None
        data = self._read()
        data["current"] = project_id
        self._write(data)
        self._current = project_id
        project["current"] = True
        return project

    def close(self) -> None:
        data = self._read()
        data["current"] = None
        self._write(data)
        self._current = None

    def delete(self, project_id: str) -> bool:
        data = self._read()
        projects = data.get("projects", [])
        target = next((p for p in projects if p.get("id") == project_id), None)
        if target is None:
            return False
        data["projects"] = [p for p in projects if p.get("id") != project_id]
        if data.get("current") == project_id:
            data["current"] = None
        self._write(data)
        return True

    # ----------------------------------------------------------------- save

    def save(
        self,
        project_id: str,
        *,
        history: Path | None = None,
        scope: Path | None = None,
        notes: list[dict[str, Any]] | None = None,
        issues: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Copy the live state into the project directory."""
        project = self.get(project_id)
        if project is None:
            return None
        directory = Path(project["path"])
        directory.mkdir(parents=True, exist_ok=True)

        if history and Path(history).exists():
            shutil.copyfile(history, directory / "history.db")
        if scope and Path(scope).exists():
            shutil.copyfile(scope, directory / "scope.json")
        if notes is not None:
            (directory / "notes.json").write_text(json.dumps(notes, indent=2))
        if issues is not None:
            (directory / "issues.json").write_text(json.dumps(issues, indent=2))
        if findings is not None:
            (directory / "findings.json").write_text(json.dumps(findings, indent=2))

        project["updated_at"] = time.time()
        (directory / "project.json").write_text(
            json.dumps({**project, "version": _VERSION}, indent=2)
        )
        data = self._read()
        data["projects"] = [p if p.get("id") != project_id else project for p in data["projects"]]
        self._write(data)
        return project

    # ----------------------------------------------------------------- load

    def load(self, project_id: str) -> dict[str, Any]:
        """Read the contents of a saved project."""
        project = self.get(project_id)
        if project is None:
            return {}
        directory = Path(project["path"])

        def _read_json(name: str) -> Any:
            try:
                return json.loads((directory / name).read_text())
            except (OSError, ValueError):
                return None

        return {
            "project": project,
            "notes": _read_json("notes.json") or [],
            "issues": _read_json("issues.json") or [],
            "findings": _read_json("findings.json") or [],
            "scope": _read_json("scope.json") or {},
            "has_history": (directory / "history.db").exists(),
            "files": sorted(p.name for p in directory.iterdir() if p.is_file()),
        }


def _slug(name: str) -> str:
    keep = [char if char.isalnum() or char in "-_" else "-" for char in name.strip().lower()]
    slug = "".join(keep).strip("-")
    return slug or "project"
