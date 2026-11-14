import click
import rich.console
import requests

import os
import sys
import time
import urllib3
import warnings
import signal
import types

from __version__ import __version__
import analysis
import visualization
import targets
import validation
import verbose
import utils
import printer


warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
CONTEXT_SETTINGS = dict(max_content_width=120, help_option_names=['-help'])
GEOIP_URL = 'https://raw.githubusercontent.com/datasets/geoip2-ipv4/refs/heads/main/data/geoip2-ipv4.csv'
GEOIP_MAX_AGE = 30 * 24 * 60 * 60  # Refresh the GeoIP database every 30 days.


def ctrl_c_signal_handler(sig: int, frame: types.FrameType | None) -> None:
    """Handle the case where the user sends a CTRL-C keyboard interrupt.

    Args:
        sig (int): Signal number (e.g., SIGINT).
        frame (FrameType | None): Current stack frame at the time of the signal.
    """
    verbose.info("'Ctrl+C!' was pressed. Exit.", False)
    os._exit(1)


def ensure_geoip_database() -> str:
    """Make sure an up-to-date GeoIP database is cached locally and return its path."""
    cache_dir = os.path.join(os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache'), 'scopez')
    geoip_filepath = os.path.join(cache_dir, 'geoip2-ipv4.csv')

    if os.path.isfile(geoip_filepath) and time.time() - os.path.getmtime(geoip_filepath) < GEOIP_MAX_AGE:
        verbose.debug(f"Use the cached GeoIP database at '{geoip_filepath}'.")
        return geoip_filepath

    verbose.info('Download the GeoIP database from GitHub.')
    try:
        response = requests.get(GEOIP_URL, timeout=300)
        response.raise_for_status()
        if not response.content.startswith(b'network,'):
            raise ValueError('unexpected file format')
        os.makedirs(cache_dir, exist_ok=True)
        tmp_filepath = f'{geoip_filepath}.tmp'
        with open(tmp_filepath, 'wb') as f:
            f.write(response.content)
        os.replace(tmp_filepath, geoip_filepath)
    except (requests.exceptions.RequestException, OSError, ValueError) as e:
        if not os.path.isfile(geoip_filepath):
            raise click.ClickException(f'Could not download the GeoIP database: {e}')
        verbose.warning(f'Could not refresh the GeoIP database ({e}). Use the cached copy.')

    return geoip_filepath


EXAMPLES = [
    (
        'Analyze a mix of targets and print tables.',
        'scopez -target 8.8.8.8,1.1.1.0/24,www.github.com,https://example.com -table',
    ),
    (
        'Analyze targets from a file and print JSON lines (logs go to stderr).',
        'scopez -list targets.txt -json > results.json',
    ),
    (
        'Read targets from STDIN and keep only the public IPs with jq.',
        'cat targets.txt | scopez -json -silent | jq -r \'select(.type == "ipv4" and .visibility == "Public") | .ipv4\'',
    ),
    (
        'Exclude out-of-scope targets.',
        'scopez -list targets.txt -exclude-file out-of-scope.txt -table',
    ),
    (
        'Draw the targets, their DNS chains and IPs as a network graph.',
        'scopez -list targets.txt -visual -output-file network.png',
    ),
    (
        'Preview how the targets are parsed without analyzing them.',
        'scopez -list targets.txt -simulate',
    ),
]


@click.command(
    context_settings=CONTEXT_SETTINGS,
    cls=utils.CustomCommand,
    no_args_is_help=True,
    examples=EXAMPLES,
)
@click.version_option(
    __version__,
    '-version',
    cls=utils.CustomOption,
    category='DEBUG',
)
@click.option(
    '-no-color',
    help='Disable colors in CLI output.',
    is_flag=True,
    cls=utils.CustomOption,
    category='DEBUG',
)
@click.option(
    '-silent',
    help='Display only results in output.',
    is_flag=True,
    cls=utils.CustomOption,
    category='DEBUG',
)
@click.option(
    '-debug',
    help='Display debug messages.',
    is_flag=True,
    cls=utils.CustomOption,
    category='DEBUG',
)
@click.option(
    '-simulate',
    help='Display the parsed targets.',
    is_flag=True,
    cls=utils.CustomOption,
    category='DEBUG',
)
@click.option(
    '-target',
    help='Targets to analyze (comma-separated).',
    type=str,
    default='',
    cls=utils.CustomOption,
    category='INPUT',
)
@click.option(
    '-list',
    help='List of targets to analyze (file).',
    type=str,
    default='',
    callback=validation.validate_file_exists,
    cls=utils.CustomOption,
    category='INPUT',
)
@click.option(
    '-exclude-targets',
    help='Targets to exclude from analysis (comma-separated).',
    type=str,
    default='',
    cls=utils.CustomOption,
    category='INPUT',
)
@click.option(
    '-exclude-file',
    help='List of targets to exclude from analysis (file).',
    type=str,
    default='',
    callback=validation.validate_file_exists,
    cls=utils.CustomOption,
    category='INPUT',
)
@click.option(
    '-table',
    help='Print the results as tables.',
    is_flag=True,
    cls=utils.CustomOption,
    category='OUTPUT',
)
@click.option(
    '-json',
    help='Print the results as JSON.',
    is_flag=True,
    cls=utils.CustomOption,
    category='OUTPUT',
)
@click.option(
    '-visual',
    help='Visualize the results as a network graph image (requires -output-file).',
    is_flag=True,
    cls=utils.CustomOption,
    category='OUTPUT',
)
@click.option(
    '-output-file',
    help='Output image file for -visual (e.g., network.png).',
    type=str,
    default='',
    cls=utils.CustomOption,
    category='OUTPUT',
)
@click.option(
    '-threads',
    help='The max number of worker threads.',
    type=click.IntRange(min=1),
    default=10,
    cls=utils.CustomOption,
    category='TWEAK',
)
def cli(
    no_color: bool,
    silent: bool,
    debug: bool,
    simulate: bool,
    target: str,
    list: str,
    exclude_targets: str,
    exclude_file: str,
    table: bool,
    json: bool,
    visual: bool,
    output_file: str,
    threads: int,
) -> None:
    #
    # Output format validation
    #

    formats = sum([table, json, visual])
    if formats > 1 or (formats == 0 and not simulate):
        raise click.UsageError('You must supply exactly one output format: -table, -json or -visual.')
    if visual and output_file == '':
        raise click.UsageError("'-visual' must be combined with '-output-file'.")
    if not visual and output_file != '':
        raise click.UsageError("'-output-file' can only be used with '-visual'.")

    #
    # Global
    #

    verbose.SILENT = silent
    verbose.HIGHLIGHT = False
    verbose.SOFT_WRAP = True
    verbose.DEBUG = debug
    verbose.CONSOLE = rich.console.Console(no_color=no_color, stderr=True)
    verbose.OUT = rich.console.Console(no_color=no_color)

    #
    # CLI signals
    #

    signal.signal(signal.SIGINT, ctrl_c_signal_handler)

    #
    # Welcome
    #

    verbose.print_banner(silent)
    verbose.warning('Use with caution. You are responsible for your actions.')

    #
    # Input
    #

    targeter = targets.Targeter()
    if target != '':
        verbose.info("Parse targets from the 'target' CLI parameter.")
        targeter.parse_targets_str(target)
    if list != '':
        verbose.info(f"Parse targets from the file located at '{list}'.")
        targeter.parse_targets_file(list)
    if target == '' and list == '' and not sys.stdin.isatty():
        verbose.info('Parse targets from the STDIN.')
        targeter.parse_targets_file('-')
    if exclude_targets != '':
        verbose.info("Exclude targets from the 'exclude_targets' CLI parameter.")
        targeter.parse_exclusions_str(exclude_targets)
    if exclude_file != '':
        verbose.info(f"Exclude targets from the file located at '{exclude_file}'.")
        targeter.parse_exclusions_file(exclude_file)

    #
    # Simulation
    #

    if simulate:
        verbose.info('Simulate and print the parsed targets.')
        targeter.print_targets()
        return

    #
    # No targets
    #

    unsupported = targeter.unsupported()
    if targeter.total_count() == 0:
        reasons = []
        if unsupported:
            reasons.append(f'unsupported (IPv6 or with a port): {", ".join(unsupported)}')
        if targeter.invalids:
            reasons.append(f'invalid: {", ".join(targeter.invalids)}')
        details = f' Skipped targets - {"; ".join(reasons)}.' if reasons else ''
        raise click.UsageError(f'You must supply at least one valid target.{details}')
    if unsupported:
        verbose.warning(f'Skipping unsupported targets (IPv6 or with a port): {", ".join(unsupported)}')

    #
    # GeoIP2
    #

    geoip_filepath = ensure_geoip_database()

    #
    # Analysis
    #

    analyzer = analysis.Analyzer()
    analyzer.parse_geoip_data(geoip_filepath)
    verbose.info('Analyze the targets.')
    if len(targeter.ipv4s) > 0:
        analyzer.analyze_ipv4s(targeter.ipv4s, threads)
    if len(targeter.cidrs_v4) > 0:
        analyzer.analyze_cidrs(targeter.cidrs_v4, threads)
    if len(targeter.fqdns) > 0:
        analyzer.analyze_fqdns(targeter.fqdns, threads)
    if len(targeter.urls) > 0:
        analyzer.analyze_urls(targeter.urls, threads)

    #
    # Output
    #

    if json:
        if len(targeter.ipv4s) > 0:
            printer.Printer.print_as_json(analyzer.analyzed_ipv4s)
        if len(targeter.cidrs_v4) > 0:
            printer.Printer.print_as_json(analyzer.analyzed_cidrs)
        if len(targeter.fqdns) > 0:
            printer.Printer.print_as_json(analyzer.analyzed_fqdns)
        if len(targeter.urls) > 0:
            printer.Printer.print_as_json(analyzer.analyzed_urls)

    elif table:
        if len(targeter.ipv4s) > 0:
            printer.Printer.print_ipv4s_as_table(analyzer.analyzed_ipv4s)
        if len(targeter.cidrs_v4) > 0:
            printer.Printer.print_cidrs_as_table(analyzer.analyzed_cidrs)
        if len(targeter.fqdns) > 0:
            printer.Printer.print_fqdns_as_table(analyzer.analyzed_fqdns)
        if len(targeter.urls) > 0:
            printer.Printer.print_urls_as_table(analyzer.analyzed_urls)
        if len(targeter.invalids) > 0:
            printer.Printer.print_invalids_as_table(targeter.invalids)

    elif visual:
        verbose.info(f"Create the visualization image at '{output_file}'.")
        visualizer = visualization.Visualizer()
        visualizer.create_visualization_image(
            analyzer.analyzed_ipv4s,
            analyzer.analyzed_cidrs,
            analyzer.analyzed_fqdns,
            analyzer.analyzed_urls,
            output_file,
        )


if __name__ == '__main__':
    cli()
