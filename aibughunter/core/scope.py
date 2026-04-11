"""Scope management system."""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class Target(BaseModel):
    """Represents a target in scope."""
    target: str
    scope_type: str  # "in" or "out"
    program: str = "default"
    notes: Optional[str] = None
    added_at: datetime = datetime.now()


class Program(BaseModel):
    """Represents a bug bounty program."""
    name: str
    platform: Optional[str] = None  # hackerone, bugcrowd, etc.
    url: Optional[str] = None
    active: bool = True
    target_count: int = 0


class ScopeManager:
    """Manages target scope and bug bounty programs."""
    
    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.scope_file = self.data_dir / "scope.json"
        self.programs_file = self.data_dir / "programs.json"
        
        self.targets = self._load_targets()
        self.programs = self._load_programs()
    
    def _load_targets(self) -> list[Target]:
        """Load targets from file."""
        if self.scope_file.exists():
            with open(self.scope_file) as f:
                data = json.load(f)
                return [Target(**t) for t in data.get("targets", [])]
        return []
    
    def _save_targets(self):
        """Save targets to file."""
        with open(self.scope_file, "w") as f:
            json.dump({
                "targets": [t.model_dump() for t in self.targets],
            }, f, indent=2, default=str)
    
    def _load_programs(self) -> list[Program]:
        """Load programs from file."""
        if self.programs_file.exists():
            with open(self.programs_file) as f:
                data = json.load(f)
                return [Program(**p) for p in data.get("programs", [])]
        return [Program(name="default")]
    
    def _save_programs(self):
        """Save programs to file."""
        with open(self.programs_file, "w") as f:
            json.dump({
                "programs": [p.model_dump() for p in self.programs],
            }, f, indent=2, default=str)
    
    def add_target(
        self,
        target: str,
        scope_type: str = "in",
        program: str = "default",
        notes: Optional[str] = None,
    ):
        """Add a target to scope."""
        self.targets.append(Target(
            target=target,
            scope_type=scope_type,
            program=program,
            notes=notes,
        ))
        self._save_targets()
    
    def remove_target(self, target: str):
        """Remove a target from scope."""
        self.targets = [t for t in self.targets if t.target != target]
        self._save_targets()
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        for t in self.targets:
            if t.target == target or target.endswith("." + t.target):
                return t.scope_type == "in"
        # Default to in-scope if no matching target found
        return True
    
    def list_targets(
        self,
        program: Optional[str] = None,
        scope_type: Optional[str] = None,
    ) -> list[Target]:
        """List targets with optional filtering."""
        results = self.targets
        
        if program:
            results = [t for t in results if t.program == program]
        
        if scope_type:
            results = [t for t in results if t.scope_type == scope_type]
        
        return results
    
    def import_scope(self, file_path: str, program: str = "default") -> int:
        """Import scope from file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {file_path}")
        
        count = 0
        
        if path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
                targets = data.get("targets", data if isinstance(data, list) else [])
                for target in targets:
                    target_str = target if isinstance(target, str) else target.get("target", target.get("domain"))
                    scope_type = target.get("scope_type", "in") if isinstance(target, dict) else "in"
                    self.add_target(target_str, scope_type=scope_type, program=program)
                    count += 1
        else:
            # Plain text, one target per line
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.add_target(line, program=program)
                        count += 1
        
        return count
    
    def export_scope(self, output_path: str, format: str = "json"):
        """Export scope to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "json":
            with open(path, "w") as f:
                json.dump({
                    "targets": [t.model_dump() for t in self.targets],
                }, f, indent=2, default=str)
        elif format == "text":
            with open(path, "w") as f:
                for target in self.targets:
                    f.write(f"{target.target}\n")
    
    def list_programs(self) -> list[Program]:
        """List all programs."""
        # Update target counts
        for program in self.programs:
            program.target_count = len([t for t in self.targets if t.program == program.name])
        return self.programs
