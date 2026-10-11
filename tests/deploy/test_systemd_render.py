import importlib.util
from pathlib import Path
import shutil

import pytest


SOURCE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "renewal_unit_renderer", SOURCE / "deploy/https/render_systemd.py"
)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


@pytest.mark.parametrize("scope", ["user", "system"])
def test_rendered_units_use_checkout_path_without_changing_templates(tmp_path, scope):
    repo = tmp_path / "custom checkout %n $HOME"
    templates = repo / "deploy/https"
    templates.mkdir(parents=True)
    for name in (
        "session-notify-https-renew.service.in",
        "session-notify-https-renew-user.service.in",
        "session-notify-https-renew.timer",
    ):
        shutil.copyfile(SOURCE / "deploy/https" / name, templates / name)
    originals = {p.name: p.read_bytes() for p in templates.iterdir()}
    output = repo / "runtime/public-https/systemd" / scope

    renderer.render_units(repo, scope, output)

    service = (output / "session-notify-https-renew.service").read_text(encoding="utf-8")
    command = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    assert "custom checkout %%n $$HOME" in command
    assert "__MANAGE_SCRIPT__" not in service
    assert ("network-online.target" in service) == (scope == "system")
    assert (output / "session-notify-https-renew.timer").read_bytes() == originals["session-notify-https-renew.timer"]
    assert {p.name: p.read_bytes() for p in templates.iterdir()} == originals
    assert b"\r\n" not in (output / "session-notify-https-renew.service").read_bytes()


def test_unit_quote_preserves_quotes_and_backslashes():
    assert renderer.unit_quote('/srv/a"b\\c') == '"/srv/a\\"b\\\\c"'


@pytest.mark.parametrize("path", ["/srv/a\nb", "/srv/a\rb", "/srv/a\tb", "/srv/a\x00b"])
def test_unit_quote_rejects_control_characters(path):
    with pytest.raises(ValueError, match="Control characters"):
        renderer.unit_quote(path)
