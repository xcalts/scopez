import click
import rich.console

import sys

import common.targets

from __version__ import __version__


@click.command()
@click.option("--list", help="List of targets to analyze.", default="")
@click.version_option(__version__)
def cli(list: str) -> None:
    console = rich.console.Console()
    console._log_render.omit_repeated_times = False

    if not sys.stdin.isatty():
        piped_input = sys.stdin.read()

    console.log("[INF] Parsing the targets from STDIN.")
    targeter = common.targets.Targeter()
    targeter.parse_targets_str(piped_input)
    targeter.print_targets()

    print(list)
    pass


if __name__ == "__main__":
    cli()
