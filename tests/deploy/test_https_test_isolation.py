from offline_support import TEST_INPUTS, prepare_test_tree


def test_https_tests_copy_only_public_inputs_from_an_existing_deployment(tmp_path):
    source = tmp_path / "existing-deployment"
    destination = tmp_path / "test-copy"
    for relative in TEST_INPUTS:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("public test input", encoding="utf-8")
    for relative in (
        "runtime/secrets/server.key",
        "runtime/session_notify.db",
        "runtime/public-https/config.env",
        "runtime/public-https/acme/accounts/account.json",
        ".git/config",
        ".venv/installed-package",
    ):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic sensitive sentinel", encoding="utf-8")

    prepare_test_tree(source, destination)

    copied = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()}
    assert copied == set(TEST_INPUTS)
    # These mkdir calls used to fail after copying an existing deployment.
    (destination / "runtime/public-https").mkdir(parents=True)
    (destination / "runtime/secrets").mkdir(parents=True)
