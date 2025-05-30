import click
import rich.console

import os
import sys
import urllib3
import warnings
import signal
import types

from __version__ import __version__
import analysis
import targets
import validation
import verbose
import utils
import print


warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
CONTEXT_SETTINGS = dict(max_content_width=120, help_option_names=["-help"])


def ctrl_c_signal_handler(sig: int, frame: types.FrameType | None) -> None:
    """Handle the case where the user sends a CTRL-C keyboard interrupt.

    Args:
        sig (int): Signal number (e.g., SIGINT).
        frame (FrameType | None): Current stack frame at the time of the signal.
    """
    verbose.info("'Ctrl+C!' was pressed. Exit.", False)
    os._exit(1)


@click.command(
    context_settings=CONTEXT_SETTINGS,
    cls=utils.CustomCommand,
)
@click.version_option(
    __version__,
    "-version",
    cls=utils.CustomOption,
    category="DEBUG",
)
@click.option(
    "-no-color",
    help="Disable colors in CLI output.",
    is_flag=True,
    cls=utils.CustomOption,
    category="DEBUG",
)
@click.option(
    "-silent",
    help="Display only results in output.",
    is_flag=True,
    cls=utils.CustomOption,
    category="DEBUG",
)
@click.option(
    "-simulate",
    help="Display the parsed targets.",
    is_flag=True,
    cls=utils.CustomOption,
    category="DEBUG",
)
@click.option(
    "-target",
    help="Targets to analyze (comma-separated).",
    type=str,
    default="",
    cls=utils.CustomOption,
    category="INPUT",
)
@click.option(
    "-list",
    help="List of targets to analyze (file).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=utils.CustomOption,
    category="INPUT",
)
@click.option(
    "-exclude-targets",
    help="Targets to exclude from analysis (comma-separated).",
    type=str,
    default="",
    cls=utils.CustomOption,
    category="INPUT",
)
@click.option(
    "-exclude-file",
    help="List of targets to exclude from analysis (file).",
    type=str,
    default="",
    callback=validation.validate_file_exists,
    cls=utils.CustomOption,
    category="INPUT",
)
@click.option(
    "-json",
    help="Write output in JSON lines format.",
    is_flag=True,
    cls=utils.CustomOption,
    category="OUTPUT",
)
@click.option(
    "-table",
    help="Write output in Table format.",
    is_flag=True,
    cls=utils.CustomOption,
    category="OUTPUT",
)
@click.option(
    "-threads",
    help="The max number of worker threads.",
    type=int,
    default=10,
    cls=utils.CustomOption,
    category="TWEAK",
)
def cli(
    no_color: bool,
    silent: bool,
    simulate: bool,
    target: str,
    list: str,
    exclude_targets: str,
    exclude_file: str,
    json: bool,
    table: bool,
    threads: int,
) -> None:
    ##########
    # Global #
    ##########
    verbose.SILENT = silent
    verbose.HIGHLIGHT = False
    verbose.SOFT_WRAP = True
    verbose.CONSOLE = rich.console.Console(no_color=no_color)

    ###############
    # CLI Signals #
    ###############
    signal.signal(signal.SIGINT, ctrl_c_signal_handler)

    ##################
    # CLI Validation #
    ##################
    if json and table:
        raise click.UsageError("You can not use '-json' and '-table' options at the same time.")

    ###########
    # Welcome #
    ###########
    verbose.print_banner(silent)
    verbose.warning("Use with caution. You are responsible for your actions.")

    #########
    # Input #
    #########
    targeter = targets.Targeter()
    if not sys.stdin.isatty():
        verbose.info("Parse targets from the STDIN.")
        targeter.parse_targets_file("-")
    elif target != "":
        verbose.info("Parse targets from the 'target' CLI parameter.")
        targeter.parse_targets_str(target)
    elif list != "":
        verbose.info(f"Parse targets from the file located at '{list}'.")
        targeter.parse_targets_file(list)
    elif exclude_targets != "":
        verbose.info("Exclude targets from the 'exclude_targets' CLI parameter.")
        targeter.parse_exclusions_str(exclude_targets)
    elif exclude_file != "":
        verbose.info(f"Exclude targets from the file located at '{exclude_file}'.")
        targeter.parse_exclusions_file(exclude_file)

    ##############
    # No Targets #
    ##############
    if targeter.total_count() == 0:
        raise click.UsageError("You must supply at least one target.")

    ##############
    # Simulation #
    ##############
    if simulate:
        verbose.info("Simulate and print the parsed targets.")
        targeter.print_targets()
        exit(1)

    ############
    # Analysis #
    ############
    analyzer = analysis.Analyzer()
    verbose.info("Analyze the targets.")
    if len(targeter.ipv4s) > 0:
        analyzer.analyze_ipv4s(targeter.ipv4s, threads)
    if len(targeter.cidrs_v4) > 0:
        analyzer.analyze_cidrs(targeter.cidrs_v4, threads)
    if len(targeter.fqdns) > 0:
        analyzer.analyze_fqdns(targeter.fqdns, threads)
    if len(targeter.urls) > 0:
        analyzer.analyze_urls(targeter.urls, threads)

    ##########
    # stdout #
    ##########
    verbose.info("Print the results in the stdout.")
    verbose.SILENT = False
    if len(targeter.ipv4s) > 0:
        if table:
            print.Printer.print_ipv4s_as_table(analyzer.analyzed_ipv4s)
        elif json:
            print.Printer.print_as_json(analyzer.analyzed_ipv4s)
        else:
            print.Printer.print_ipv4s_as_raw(analyzer.analyzed_ipv4s)
    if len(targeter.cidrs_v4) > 0:
        if table:
            print.Printer.print_cidrs_as_table(analyzer.analyzed_cidrs)
        elif json:
            print.Printer.print_as_json(analyzer.analyzed_cidrs)
        else:
            print.Printer.print_cidrs_as_raw(analyzer.analyzed_cidrs)
    if len(targeter.fqdns) > 0:
        if table:
            print.Printer.print_fqdns_as_table(analyzer.analyzed_fqdns)
        elif json:
            print.Printer.print_as_json(analyzer.analyzed_fqdns)
        else:
            print.Printer.print_fqdns_as_raw(analyzer.analyzed_fqdns)
    if len(targeter.urls) > 0:
        if table:
            print.Printer.print_urls_as_table(analyzer.analyzed_urls)
        elif json:
            print.Printer.print_as_json(analyzer.analyzed_urls)
        else:
            print.Printer.print_urls_as_raw(analyzer.analyzed_urls)

    ############
    # Beautify #
    ############
    verbose.normal("\n")


if __name__ == "__main__":
    cli()
