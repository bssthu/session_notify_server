"""Run the real Linux updater against isolated, offline command doubles."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2]


class UpdateFlow(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="update-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout with spaces"
        (self.root / "deploy/https").mkdir(parents=True)
        shutil.copyfile(SOURCE / "deploy/update-server.sh", self.root / "deploy/update-server.sh")
        (self.root / "runtime/secrets").mkdir(parents=True)
        (self.root / "runtime/secrets/server.crt").write_text("synthetic certificate")
        (self.root / "runtime/deploy").mkdir()
        self.configure("UPDATE_HEALTH_RETRIES=2\nUPDATE_HEALTH_INTERVAL_SECONDS=0\n")
        binaries = self.root / "bin"
        binaries.mkdir()
        scripts = {
            "git": r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_ROOT/git.log"
case "$*" in
  'rev-parse --show-toplevel') printf '%s\n' "$TEST_ROOT";;
  'status --porcelain') [[ ! -f "$TEST_ROOT/dirty" ]] || echo ' M tracked-file'; exit 0;;
  'symbolic-ref --quiet --short HEAD') [[ ! -f "$TEST_ROOT/detached" ]] || exit 1; echo main;;
  "rev-parse --abbrev-ref --symbolic-full-name @{upstream}") [[ ! -f "$TEST_ROOT/no-upstream" ]] || exit 1; echo origin/main;;
  'rev-parse --short HEAD') echo fixture-commit;;
  'pull --ff-only') [[ ! -f "$TEST_ROOT/pull-fails" ]];;
esac
''',
            "docker": r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_ROOT/docker.log"
case "$*" in
  *'ps --all -q server') [[ ! -f "$TEST_ROOT/missing-server" ]] || exit 0; echo existing-server;;
  *'config --quiet') [[ ! -f "$TEST_ROOT/bad-compose" ]];;
  *'up -d --build server') [[ ! -f "$TEST_ROOT/build-fails" ]];;
esac
''',
            "curl": r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_ROOT/curl.log"
[[ ! -f "$TEST_ROOT/unhealthy" ]] || exit 22
if [[ -f "$TEST_ROOT/wrong-body" ]]; then echo '{"status":"starting"}'; else echo '{"status":"ok"}'; fi
''',
        }
        for name, content in scripts.items():
            path = binaries / name
            path.write_text(content)
            path.chmod(0o755)
        (self.root / "deploy/https/manage.sh").write_text(r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_ROOT/https.log"
case "$*" in
  'compose ps --all -q server') if [[ -f "$TEST_ROOT/wrong-project" ]]; then echo wrong-server; else echo existing-server; fi;;
  'compose ps --all -q public-https') [[ ! -f "$TEST_ROOT/missing-frontend" ]] || exit 0; echo existing-frontend;;
  'compose pull public-https public-certbot') [[ ! -f "$TEST_ROOT/image-pull-fails" ]];;
  'activate') [[ ! -f "$TEST_ROOT/activation-fails" ]];;
esac
''')
        self.env = dict(os.environ, PATH=str(binaries) + ":" + os.environ["PATH"], TEST_ROOT=str(self.root))
        for key in list(self.env):
            if key.startswith("UPDATE_"):
                del self.env[key]

    def configure(self, value):
        (self.root / "runtime/deploy/update.env").write_text(value)

    def mark(self, name):
        (self.root / name).touch()

    def log(self, name):
        path = self.root / (name + ".log")
        return path.read_text() if path.exists() else ""

    def invoke(self, *arguments, success=True):
        result = subprocess.run(
            ["bash", str(self.root / "deploy/update-server.sh"), *arguments],
            cwd=str(self.root.parent), env=self.env, universal_newlines=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def activate_fixture(self):
        live = self.root / "runtime/public-https/acme/live/session-notify-public"
        live.mkdir(parents=True)
        (live / "cert.pem").write_text("synthetic public certificate")
        nginx = self.root / "runtime/public-https/nginx"
        nginx.mkdir()
        (nginx / "default.conf").write_text("ssl_certificate fixture;\n")

    def test_default_pull_reenters_once_and_updates_backend_only(self):
        self.invoke()
        self.assertEqual(self.log("git").count("pull --ff-only\n"), 1)
        self.assertEqual(self.log("docker").count("up -d --build server\n"), 1)
        self.assertIn("--cacert runtime/secrets/server.crt", self.log("curl"))
        self.assertNotIn("--insecure", self.log("curl"))
        self.assertEqual(self.log("https"), "")

    def test_configurable_project_and_health_port(self):
        self.configure("UPDATE_COMPOSE_PROJECT=custom-project\nUPDATE_HEALTH_URL=https://127.0.0.1:9876/health\n")
        self.invoke("--no-pull")
        self.assertIn("--project-name custom-project up -d --build server", self.log("docker"))
        self.assertIn("https://127.0.0.1:9876/health", self.log("curl"))
        self.assertNotIn("pull", self.log("git"))

    def test_preflight_failures_never_rebuild(self):
        for marker in ("dirty", "missing-server", "detached", "no-upstream", "pull-fails", "bad-compose"):
            with self.subTest(marker=marker):
                self.mark(marker)
                self.invoke(success=False)
                self.assertNotIn("up -d --build", self.log("docker"))
                (self.root / marker).unlink()

    def test_no_pull_allows_detached_checkout(self):
        self.mark("detached")
        self.invoke("--no-pull")

    def test_build_failure_stops_before_health(self):
        self.mark("build-fails")
        self.invoke("--no-pull", success=False)
        self.assertEqual(self.log("curl"), "")

    def test_backend_failure_stops_before_frontend_update(self):
        self.activate_fixture()
        self.mark("unhealthy")
        self.invoke("--no-pull", "--https", success=False)
        self.assertNotIn("up -d --no-deps", self.log("https"))
        self.assertNotIn("activate", self.log("https"))

    def test_http_success_without_healthy_body_is_rejected(self):
        self.mark("wrong-body")
        self.invoke("--no-pull", success=False)

    def test_https_requires_existing_activated_deployment(self):
        self.invoke("--no-pull", "--https", success=False)
        self.assertNotIn("up -d --build", self.log("docker"))

    def test_https_rejects_different_project_and_missing_frontend(self):
        self.activate_fixture()
        for marker in ("wrong-project", "missing-frontend"):
            with self.subTest(marker=marker):
                self.mark(marker)
                self.invoke("--no-pull", "--https", success=False)
                self.assertNotIn("up -d --build", self.log("docker"))
                (self.root / marker).unlink()

    def test_https_update_applies_existing_frontend_without_issuance(self):
        self.activate_fixture()
        self.invoke("--https")
        commands = self.log("https")
        self.assertIn("compose pull public-https public-certbot", commands)
        self.assertIn("compose up -d --no-deps public-https", commands)
        self.assertIn("activate\n", commands)
        for forbidden in ("issue", "bootstrap", "renew", "systemctl", "443"):
            self.assertNotIn(forbidden, commands)

    def test_frontend_image_pull_failure_keeps_backend_untouched(self):
        self.activate_fixture()
        self.mark("image-pull-fails")
        self.invoke("--no-pull", "--https", success=False)
        self.assertNotIn("up -d --build", self.log("docker"))

    def test_frontend_activation_failure_is_reported(self):
        self.activate_fixture()
        self.mark("activation-fails")
        self.invoke("--no-pull", "--https", success=False)

    def test_invalid_health_settings_fail_before_update(self):
        for config in ("UPDATE_HEALTH_URL=http://127.0.0.1/health", "UPDATE_HEALTH_RETRIES=0", "UPDATE_HEALTH_INTERVAL_SECONDS=-1"):
            with self.subTest(config=config):
                self.configure(config + "\n")
                self.invoke("--no-pull", success=False)
                self.assertNotIn("up -d --build", self.log("docker"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
