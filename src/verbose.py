import rich.console

from __version__ import __version__

SILENT = False
HIGHLIGHT = False
SOFT_WRAP = False
CONSOLE = {}


def print_banner(silent: bool, highlight: bool = True) -> None:
    logo = f"""
 ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▄▄▖ ▗▄▄▄▖▗▄▄▄▄▖
▐▌   ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌      ▗▞▘
 ▝▀▚▖▐▌   ▐▌ ▐▌▐▛▀▘ ▐▛▀▀▘ ▗▞▘  
▗▄▄▞▘▝▚▄▄▖▝▚▄▞▘▐▌   ▐▙▄▄▖▐▙▄▄▄▖ {__version__}
        
        https://github.com/xcalts/scopez
"""
    if not silent:
        CONSOLE.print(logo, highlight=False)


def critical(message: str) -> None:
    if not SILENT:
        CONSOLE.print(f"[bold red][CRITICAL][/bold red] {message}", highlight=HIGHLIGHT, soft_wrap=SOFT_WRAP)


def error(message: str) -> None:
    if not SILENT:
        CONSOLE.print(f"[red][ERROR]   [/red] {message}", highlight=HIGHLIGHT, soft_wrap=SOFT_WRAP)


def warning(message: str) -> None:
    if not SILENT:
        CONSOLE.print(f"[yellow][WARNING] [/yellow] {message}", highlight=HIGHLIGHT, soft_wrap=SOFT_WRAP)


def info(message: str) -> None:
    if not SILENT:
        CONSOLE.print(f"[green][INFO]    [/green] {message}", highlight=HIGHLIGHT, soft_wrap=SOFT_WRAP)


def debug(message: str) -> None:
    if not SILENT:
        CONSOLE.print(f"[blue][DEBUG]   [/blue] {message}", highlight=HIGHLIGHT, soft_wrap=SOFT_WRAP)


def normal(message: str) -> None:
    if not SILENT:
        CONSOLE.print(message, highlight=HIGHLIGHT, soft_wrap=SOFT_WRAP)
