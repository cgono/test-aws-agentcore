from importlib.metadata import version


def test_package_metadata_is_installed() -> None:
    assert version("agentcore-identity-poc") == "0.1.0"
