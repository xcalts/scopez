import click
import rich.console

import sys

import targets
import validation

from __version__ import __version__


class Categories(click.Command):
    """It instructs the `click` library to list commands in the order that we define their functions."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """List the commands in the order that we define their functions.

        Args:
            ctx (click.Context): The click context.

        Returns:
            list[str]: The list of commands in the order that we define their functions.
        """
        return list(self.commands)

    def format_options(self, ctx, formatter):
        categories = {}
        for param in self.get_params(ctx):
            if isinstance(param, click.Option):
                cat = getattr(param, "category", "OTHER")
                categories.setdefault(cat, []).append(param)
        for category, params in categories.items():
            with formatter.section(category):
                formatter.write_dl([(p.opts[0], p.help or "") for p in params])


class CategoryOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.category = kwargs.pop("category", None)
        super().__init__(*args, **kwargs)


CONTEXT_SETTINGS = dict(max_content_width=120, help_option_names=["-help"])


@click.command(
    context_settings=CONTEXT_SETTINGS,
    cls=Categories,
)
@click.option(
    "-target",
    help="Targets to analyze (comma-separated).",
    type=str,
    default="",
    cls=CategoryOption,
    category="INPUT",
)
@click.option(
    "-list",
    help="List of targets to analyze (file).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=CategoryOption,
    category="INPUT",
)
@click.option(
    "-exclude-targets",
    help="Targets to exclude from analysis (comma-separated).",
    type=str,
    default="",
    cls=CategoryOption,
    category="INPUT",
)
@click.option(
    "-exclude-file",
    help="List of targets to exclude from analysis (file).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=CategoryOption,
    category="INPUT",
)
@click.option(
    "-output",
    help="File to write output to (optional).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=CategoryOption,
    category="OUTPUT",
)
@click.option(
    "-json",
    help="Write output in JSON lines format.",
    type=bool,
    default=False,
    is_flag=True,
    cls=CategoryOption,
    category="OUTPUT",
)
@click.option(
    "-csv",
    help="Write output in csv format.",
    type=bool,
    default=False,
    is_flag=True,
    cls=CategoryOption,
    category="OUTPUT",
)
@click.option(
    "-no-color",
    help="Disable colors in CLI output.",
    type=bool,
    default=False,
    is_flag=True,
    cls=CategoryOption,
    category="DEBUG",
)
@click.option(
    "-silent",
    help="Display only results in output.",
    type=bool,
    default=False,
    is_flag=True,
    cls=CategoryOption,
    category="DEBUG",
)
@click.version_option(
    __version__,
    "-version",
    cls=CategoryOption,
    category="DEBUG",
)
def cli(
    target: str,
    list: str,
    exclude_targets: str,
    exclude_file: str,
    output: str,
    json: bool,
    csv: bool,
    no_color: bool,
    silent: bool,
) -> None:
    console = rich.console.Console()
    console._log_render.omit_repeated_times = False

    print(exclude_file)

    if not sys.stdin.isatty():
        piped_input = sys.stdin.read()

        console.log("[INF] Parsing the targets from STDIN.")
        targeter = targets.Targeter()
        targeter.parse_targets_str(piped_input)
        targeter.print_targets()


if __name__ == "__main__":
    cli()
