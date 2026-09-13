from pathlib import Path

from vulnhunter.config import REPOSITORY_ROOT, Settings


def test_repository_root_points_to_project_directory():
    expected_root = Path(__file__).resolve().parents[2]

    assert REPOSITORY_ROOT == expected_root


def test_default_report_directory_is_inside_project(monkeypatch):
    monkeypatch.delenv("REPORT_DIR", raising=False)

    assert Settings().report_dir == REPOSITORY_ROOT / "artifacts" / "reports"
