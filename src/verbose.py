import rich.console
from rich.logging import RichHandler

import logging
import logging.handlers

from __version__ import __version__


#################
# Setup logging #
#################
LOGFORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGFORMAT_RICH = "%(message)s"
error_console = rich.console.Console(stderr=True)
rh = RichHandler(console=error_console)
rh._log_render.omit_repeated_times = False
rh.setFormatter(logging.Formatter(LOGFORMAT_RICH))
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, handlers=[rh])
log = logging.getLogger()
console = rich.console.Console()


def print_banner() -> None:
    logo = f"""
 ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▄▄▖ ▗▄▄▄▖▗▄▄▄▄▖
▐▌   ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌      ▗▞▘
 ▝▀▚▖▐▌   ▐▌ ▐▌▐▛▀▘ ▐▛▀▀▘ ▗▞▘  
▗▄▄▞▘▝▚▄▄▖▝▚▄▞▘▐▌   ▐▙▄▄▖▐▙▄▄▄▖ {__version__}
        
        https://github.com/xcalts/scopez
"""

    console.print(logo, highlight=False)


def warning(message: str) -> None:
    log.warning(message)


def information(message: str) -> None:
    log.info(message)
