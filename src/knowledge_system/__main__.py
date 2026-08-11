"""Command-line interface."""

import typer


app: typer.Typer = typer.Typer()


@app.command(name="knowledge-system")
def main() -> None:
    """Knowledge System."""


if __name__ == "__main__":
    app()  # pragma: no cover
