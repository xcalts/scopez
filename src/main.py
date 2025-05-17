import click

import sys

from __version__ import __version__
import cidrs
import fqdns
import ipv4s
import targets
import validation
import verbose


class CustomOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.category = kwargs.pop("category", None)
        super().__init__(*args, **kwargs)


class CustomCommand(click.Command):
    """It instructs the `click` library to list commands in the order that we define their functions."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        """
        List the commands in the order that we define their functions.

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


CONTEXT_SETTINGS = dict(max_content_width=120, help_option_names=["-help"])


@click.command(
    context_settings=CONTEXT_SETTINGS,
    cls=CustomCommand,
)
@click.version_option(
    __version__,
    "-version",
    cls=CustomOption,
    category="DEBUG",
)
@click.option(
    "-target",
    help="Targets to analyze (comma-separated).",
    type=str,
    default="",
    cls=CustomOption,
    category="INPUT",
)
@click.option(
    "-list",
    help="List of targets to analyze (file).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=CustomOption,
    category="INPUT",
)
@click.option(
    "-exclude-targets",
    help="Targets to exclude from analysis (comma-separated).",
    type=str,
    default="",
    cls=CustomOption,
    category="INPUT",
)
@click.option(
    "-exclude-file",
    help="List of targets to exclude from analysis (file).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=CustomOption,
    category="INPUT",
)
@click.option(
    "-output",
    help="File to write output to (optional).",
    type=str,
    default="",
    cls=CustomOption,
    category="OUTPUT",
)
@click.option(
    "-json",
    help="Write output in JSON lines format.",
    is_flag=True,
    cls=CustomOption,
    category="OUTPUT",
)
@click.option(
    "-table",
    help="Write output in Table format.",
    is_flag=True,
    cls=CustomOption,
    category="OUTPUT",
)
@click.option(
    "-no-color",
    help="Disable colors in CLI output.",
    is_flag=True,
    cls=CustomOption,
    category="DEBUG",
)
@click.option(
    "-silent",
    help="Display only results in output.",
    is_flag=True,
    cls=CustomOption,
    category="DEBUG",
)
def cli(
    target: str,
    list: str,
    exclude_targets: str,
    exclude_file: str,
    output: str,
    json: bool,
    table: bool,
    no_color: bool,
    silent: bool,
) -> None:

    ##############
    # Validation #
    ##############
    if json and table:
        raise click.UsageError("You can not use '-json' & '-table' options at the same time.")

    #########
    # Input #
    #########
    targeter = targets.Targeter()
    if not sys.stdin.isatty():
        if not silent:
            verbose.information("Parsing targets from the STDIN.")
        targeter.parse_targets_file("-")
    elif target != "":
        if not silent:
            verbose.information("Parsing targets from the 'target' CLI parameter.")
        targeter.parse_targets_str(target)
    elif list != "":
        if not silent:
            verbose.information(f"Parsing targets from the file located at '{list}'.")
        targeter.parse_targets_file(list)
    elif exclude_targets != "":
        if not silent:
            verbose.information("Excluding targets from the 'exclude_targets' CLI parameter.")
        targeter.parse_exclusions_str(exclude_targets)
    elif exclude_file != "":
        if not silent:
            verbose.information(f"Excluding targets from the file located at '{exclude_file}'.")
        targeter.parse_exclusions_file(exclude_file)

    ###########
    # Welcome #
    ###########
    if not silent:
        verbose.print_banner()

        if targeter.total_count() == 0:
            exit(1)

        verbose.warning("Use with caution. You are responsible for your actions.")

    ############
    # Analysis #
    ############
    results = []
    if not silent:
        verbose.information("Analyzing the targets.")
    if len(targeter.ipv4) > 0:
        ipv4s_ = ipv4s.analyze(targeter.ipv4)
        if json:
            ipv4s.print_as_json(ipv4s_, not no_color)
        elif table:
            ipv4s.print_as_table(ipv4s_, not no_color)
        else:
            ipv4s.print_as_normal(ipv4s_, not no_color)
        results = results + ipv4s.get_results(ipv4s_)
    if len(targeter.cidr_ipv4) > 0:
        cidr_ipv4_ = cidrs.analyze(targeter.cidr_ipv4, are_v4=True)
        if json:
            cidrs.print_as_json(cidr_ipv4_, not no_color)
        elif table:
            cidrs.print_as_table(cidr_ipv4_, not no_color)
        else:
            cidrs.print_as_normal(cidr_ipv4_, not no_color)
        results = results + cidrs.get_results(cidr_ipv4_)
    if len(targeter.fqdn) > 0:
        fqdns_ = fqdns.analyze(targeter.fqdn)
        if json:
            fqdns.print_as_json(fqdns_, not no_color)
        elif table:
            fqdns.print_as_table(fqdns_, not no_color)
        else:
            fqdns.print_as_normal(fqdns_, not no_color)
        results = results + fqdns.get_results(fqdns_)

    ##########
    # Output #
    ##########
    if output != "":
        with open(output, "w") as f:
            for r in results:
                f.write(r)
                f.write("\n")


if __name__ == "__main__":
    cli()
