import click

import common.click

from __version__ import __version__


@click.group(
    cls=common.click.OrderCommands,
    context_settings={"max_content_width": 120},
)
@click.version_option(__version__)
def cli():
    pass


if __name__ == "__main__":
    cli()
