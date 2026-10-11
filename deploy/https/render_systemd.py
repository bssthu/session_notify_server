"""Render renewal units for this checkout; never install or enable them."""

import argparse
from pathlib import Path
import sys


def unit_quote(value):
    """Quote an ExecStart argument, escaping specifiers and dollar expansion."""
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Control characters are not supported in deployment paths")
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    value = value.replace("$", "$$")
    return '"' + value + '"'


def render_units(repo, scope, output):
    repo = repo.resolve()
    templates = repo / "deploy" / "https"
    name = "session-notify-https-renew"
    template = name + ("-user" if scope == "user" else "") + ".service.in"
    service = (templates / template).read_text(encoding="utf-8")
    service = service.replace(
        "__MANAGE_SCRIPT__", unit_quote(str(templates / "manage.sh"))
    )
    timer = (templates / (name + ".timer")).read_text(encoding="utf-8")
    output.mkdir(parents=True, exist_ok=True)
    for suffix, content in ((".service", service), (".timer", timer)):
        path = output / (name + suffix)
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("user", "system"), required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Generate units on the target Linux Docker host")
    repo = Path(__file__).resolve().parents[2]
    output = repo / "runtime" / "public-https" / "systemd" / args.scope
    try:
        render_units(repo, args.scope, output)
    except ValueError as error:
        parser.error(str(error))
    print("Generated units in {}. Review and install them as documented.".format(output))


if __name__ == "__main__":
    main()
