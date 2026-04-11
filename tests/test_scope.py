"""Tests for scope management."""

import json
import pytest
from pathlib import Path
from datetime import datetime

from aibughunter.core.scope import ScopeManager, Target, Program


@pytest.fixture
def scope_manager(tmp_path):
    """Create a scope manager with temporary directory."""
    return ScopeManager(data_dir=str(tmp_path / "data"))


class TestTarget:
    """Test Target model."""
    
    def test_create_target(self):
        """Test creating a target."""
        target = Target(
            target="example.com",
            scope_type="in",
            program="hackerone",
        )
        
        assert target.target == "example.com"
        assert target.scope_type == "in"
        assert target.program == "hackerone"
        assert isinstance(target.added_at, datetime)


class TestScopeManager:
    """Test scope management functionality."""
    
    def test_add_target(self, scope_manager):
        """Test adding a target."""
        scope_manager.add_target("example.com", scope_type="in", program="default")
        
        assert len(scope_manager.targets) == 1
        assert scope_manager.targets[0].target == "example.com"
    
    def test_remove_target(self, scope_manager):
        """Test removing a target."""
        scope_manager.add_target("example.com")
        scope_manager.add_target("test.com")
        
        scope_manager.remove_target("example.com")
        
        assert len(scope_manager.targets) == 1
        assert all(t.target != "example.com" for t in scope_manager.targets)
    
    def test_is_in_scope(self, scope_manager):
        """Test scope checking."""
        scope_manager.add_target("example.com", scope_type="in")
        
        assert scope_manager.is_in_scope("example.com") is True
        assert scope_manager.is_in_scope("sub.example.com") is True
    
    def test_is_out_of_scope(self, scope_manager):
        """Test out-of-scope checking."""
        scope_manager.add_target("example.com", scope_type="out")
        
        assert scope_manager.is_in_scope("example.com") is False
    
    def test_default_scope(self, scope_manager):
        """Test default behavior for unknown targets."""
        # Unknown targets default to in-scope
        assert scope_manager.is_in_scope("unknown.com") is True
    
    def test_list_targets(self, scope_manager):
        """Test listing targets."""
        scope_manager.add_target("example.com", program="prog1")
        scope_manager.add_target("test.com", program="prog2")
        
        all_targets = scope_manager.list_targets()
        assert len(all_targets) == 2
        
        prog1_targets = scope_manager.list_targets(program="prog1")
        assert len(prog1_targets) == 1
        assert prog1_targets[0].program == "prog1"
    
    def test_list_targets_by_type(self, scope_manager):
        """Test filtering by scope type."""
        scope_manager.add_target("in-scope.com", scope_type="in")
        scope_manager.add_target("out-scope.com", scope_type="out")
        
        in_targets = scope_manager.list_targets(scope_type="in")
        out_targets = scope_manager.list_targets(scope_type="out")
        
        assert len(in_targets) == 1
        assert len(out_targets) == 1
    
    def test_import_scope_from_json(self, scope_manager, tmp_path):
        """Test importing scope from JSON file."""
        scope_file = tmp_path / "scope.json"
        scope_data = {
            "targets": [
                {"target": "example.com", "scope_type": "in"},
                {"target": "test.com", "scope_type": "in"},
            ]
        }
        scope_file.write_text(json.dumps(scope_data))
        
        count = scope_manager.import_scope(str(scope_file), program="test")
        
        assert count == 2
        assert len(scope_manager.targets) == 2
    
    def test_import_scope_from_text(self, scope_manager, tmp_path):
        """Test importing scope from text file."""
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("example.com\ntest.com\n# comment\n")
        
        count = scope_manager.import_scope(str(scope_file), program="test")
        
        assert count == 2
    
    def test_export_scope_json(self, scope_manager, tmp_path):
        """Test exporting scope to JSON."""
        scope_manager.add_target("example.com", scope_type="in")
        
        output_file = tmp_path / "export.json"
        scope_manager.export_scope(str(output_file), format="json")
        
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert len(data["targets"]) == 1
    
    def test_export_scope_text(self, scope_manager, tmp_path):
        """Test exporting scope to text."""
        scope_manager.add_target("example.com")
        scope_manager.add_target("test.com")
        
        output_file = tmp_path / "export.txt"
        scope_manager.export_scope(str(output_file), format="text")
        
        content = output_file.read_text()
        assert "example.com" in content
        assert "test.com" in content
    
    def test_list_programs(self, scope_manager):
        """Test listing programs."""
        scope_manager.add_target("example.com", program="prog1")
        scope_manager.add_target("test.com", program="prog2")
        
        programs = scope_manager.list_programs()
        
        assert len(programs) >= 2  # At least our 2 programs
        prog_names = [p.name for p in programs]
        assert "prog1" in prog_names
        assert "prog2" in prog_names
    
    def test_persistence(self, scope_manager):
        """Test targets are persisted to disk."""
        scope_manager.add_target("example.com")
        
        # Create new instance
        new_manager = ScopeManager(data_dir=scope_manager.data_dir)
        assert len(new_manager.targets) == 1
        assert new_manager.targets[0].target == "example.com"
    
    def test_import_nonexistent_file(self, scope_manager):
        """Test importing from missing file raises error."""
        with pytest.raises(FileNotFoundError):
            scope_manager.import_scope("/nonexistent/scope.json")
    
    def test_subdomain_matching(self, scope_manager):
        """Test subdomain is in scope if parent is."""
        scope_manager.add_target("example.com", scope_type="in")
        
        assert scope_manager.is_in_scope("api.example.com") is True
        assert scope_manager.is_in_scope("sub.api.example.com") is True
