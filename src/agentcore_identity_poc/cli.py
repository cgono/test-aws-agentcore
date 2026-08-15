"""Command-line entry point for the AgentCore Identity POC."""

import typer

app = typer.Typer(add_completion=False)


@app.callback()
def main() -> None:
    """Run AgentCore Identity POC commands."""
