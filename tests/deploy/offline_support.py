"""Copy only the public inputs needed by isolated deployment tests."""

from pathlib import Path
import shutil


TEST_INPUTS = (
    "compose.https.yaml",
    "deploy/https/manage.sh",
    "deploy/https/bootstrap.conf",
    "deploy/https/https.conf.template",
)


def prepare_test_tree(source: Path, destination: Path) -> None:
    """Never traverse runtime, Git data, environments, or unrelated source files."""
    for relative in TEST_INPUTS:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
