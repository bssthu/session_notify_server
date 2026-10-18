"""Linux-only checks of the actual kernel lock and Certbot ownership helper."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "deploy/https/gateway"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="Requires Linux filesystem/process semantics")


def test_renewal_lock_serializes_separate_processes(monkeypatch):
    sys.path.insert(0, str(DIRECTORY))
    import gateway
    sys.path.remove(str(DIRECTORY))
    with tempfile.TemporaryDirectory(prefix="session-notify-gateway-lock-") as temporary:
        monkeypatch.setattr(gateway, "WORK", Path(temporary))
        script = "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); import gateway; gateway.WORK=Path(sys.argv[2]);\nwith gateway.operation_lock(): print('acquired', flush=True)"
        child = None
        try:
            with gateway.operation_lock():
                child = subprocess.Popen([sys.executable, "-c", script, str(DIRECTORY), temporary], stdout=subprocess.PIPE, text=True)
                with pytest.raises(subprocess.TimeoutExpired):
                    child.communicate(timeout=0.25)
            output, _ = child.communicate(timeout=10)
            assert child.returncode == 0
            assert output.strip() == "acquired"
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait()


def test_fixed_root_identity_can_preserve_old_key_group():
    if os.geteuid() != 0:
        pytest.skip("Root fixture required to reproduce the deployed UID/GID mismatch")
    filesystem = pytest.importorskip("certbot.compat.filesystem")
    # Synthetic text files only. Never reads a real key or certificate directory.
    with tempfile.TemporaryDirectory(prefix="session-notify-gateway-group-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        old, new = root / "old", root / "new"
        old.write_text("synthetic-old")
        new.write_text("synthetic-new")
        os.chown(old, 1000, 1000)
        os.chown(new, 1000, 111)
        old.chmod(0o600)
        new.chmod(0o600)
        script = "import os,sys; from certbot.compat import filesystem; os.setgroups([]); os.setgid(111); os.setuid(1000); filesystem.copy_ownership_and_apply_mode(sys.argv[1], sys.argv[2], 0o600, copy_user=False, copy_group=True)"
        failed = subprocess.run([sys.executable, "-c", script, str(old), str(new)], capture_output=True, text=True, timeout=10)
        assert failed.returncode != 0
        assert "PermissionError" in failed.stderr
        filesystem.copy_ownership_and_apply_mode(str(old), str(new), 0o600, copy_user=False, copy_group=True)
        assert new.stat().st_gid == 1000
        assert new.stat().st_mode & 0o777 == 0o600
