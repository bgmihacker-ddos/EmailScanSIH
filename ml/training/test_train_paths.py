from pathlib import Path

from ml.training.train import ROOT, resolve_repo_path


def test_resolve_repo_path_returns_absolute_path_for_missing_repo_relative_file():
    resolved = resolve_repo_path(Path("ml/datasets/real/does-not-exist.jsonl"))

    assert resolved.is_absolute()
    assert resolved == (ROOT / "ml/datasets/real/does-not-exist.jsonl").resolve()