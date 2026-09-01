import subprocess
import sys
from importlib.metadata import version
from pathlib import Path


def test_package_metadata_is_installed() -> None:
    assert version("agentcore-identity-poc") == "0.1.0"


def test_console_script_help_succeeds() -> None:
    command = Path(sys.executable).parent / "agentcore-identity-poc"
    assert command.is_file()
    result = subprocess.run(  # noqa: S603
        [str(command), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
