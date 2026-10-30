"""Named Git objects, rather than the evaluator's HEAD, bind the scanner candidate."""

import hashlib

from evaluation import run_holdout


def test_candidate_pin_reads_named_commit_even_when_head_differs(monkeypatch):
    commit = "a" * 40
    paths = ["backend/main.py", "uv.lock"]
    blobs = {"backend/main.py": b"named runtime", "uv.lock": b"named dependencies"}
    calls = []

    def git(args, **kwargs):
        calls.append(args)
        assert kwargs["cwd"] == run_holdout.ROOT
        if args[1] == "ls-tree":
            assert args[5] == commit
            return ("\0".join(paths) + "\0").encode()
        assert args[:2] == ["git", "show"]
        assert args[2].startswith(commit + ":")
        return blobs[args[2].split(":", 1)[1]]

    monkeypatch.setattr(run_holdout.subprocess, "check_output", git)
    monkeypatch.setattr(run_holdout, "source_fingerprint", lambda: "different-local-head")
    expected = hashlib.sha256(
        "\n".join(path + ":" + hashlib.sha256(blobs[path]).hexdigest() for path in paths).encode()
    ).hexdigest()
    assert run_holdout.candidate_source_fingerprint(commit) == expected
    assert all("HEAD" not in command for command in calls)


def test_runtime_pin_excludes_vendor_but_detects_tracked_changes(monkeypatch, tmp_path):
    commit = "a" * 40
    monkeypatch.setattr(run_holdout, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        run_holdout.subprocess, "check_output", lambda *args, **kwargs: b"uv.lock\0"
    )
    (tmp_path / "uv.lock").write_bytes(b"pinned")
    vendor = tmp_path / "workers/vendor"
    vendor.mkdir(parents=True)
    (vendor / "binary.zip").write_bytes(b"untracked vendor")
    expected = hashlib.sha256(
        ("uv.lock:" + hashlib.sha256(b"pinned").hexdigest()).encode()
    ).hexdigest()
    assert run_holdout.candidate_source_fingerprint(commit, runtime=True) == expected
    (tmp_path / "uv.lock").write_bytes(b"changed")
    assert run_holdout.candidate_source_fingerprint(commit, runtime=True) != expected
