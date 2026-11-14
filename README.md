<a id="readme-top"></a>

<!-- PROJECT LOGO -->
<br />

<div align="center">

[![Python][python-shield]][python-url]
[![Linux][linux-shield]][linux-url]
[![MacOS][macos-shield]][macos-url]
[![Stars][stars-shield]][stars-url]
[![Contributors][contributors-shield]][contributors-url]
[![Issues][issues-shield]][issues-url]

  <h1>Scopez</h1>
  
  <p align="center">
    Scopez verifies connectivity to target servers, reveals CDN presence, and provides detailed target insights like reachability and RDAP.
    <br />
    <br />
    <a href="https://github.com/xcalts/scopez/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/xcalts/scopez/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
    ·
    <a href="https://pypi.org/project/scopez/">PyPI</a>
  </p>

</div>

## Installation

You can install `scopez` using `uv`.

```
uv tool install scopez
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Features

- Parses a file filled with targets
- Does IP network **math**
- Captures **RDAP** data
- **Pings** IPs and FQDNs
- Displays **DNS chains**
- Unix friendly input/output
- **Threads** support
- Multiple input support - **STDIN/FILE/CIDR/IP/FQDN/URL**
- Multiple output formats - **TABLE/JSON** (stdout) and **PNG** network graph
- Visualize the network using a graph

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

```
Usage: scopez [OPTIONS]

DEBUG:
  -version   Show the version and exit.
  -no-color  Disable colors in CLI output.
  -silent    Display only results in output.
  -debug     Display debug messages.
  -simulate  Display the parsed targets.

INPUT:
  -target           Targets to analyze (comma-separated).
  -list             List of targets to analyze (file).
  -exclude-targets  Targets to exclude from analysis (comma-separated).
  -exclude-file     List of targets to exclude from analysis (file).

OUTPUT:
  -table        Print the results as tables.
  -json         Print the results as JSON.
  -visual       Visualize the results as a network graph image (requires -output-file).
  -output-file  Output image file for -visual (e.g., network.png).

TWEAK:
  -threads  The max number of worker threads.

OTHER:
  -help  Show this message and exit.

EXAMPLES:
  # Analyze a mix of targets and print tables.
  scopez -target 8.8.8.8,1.1.1.0/24,www.github.com,https://example.com -table

  # Analyze targets from a file and print JSON lines (logs go to stderr).
  scopez -list targets.txt -json > results.json

  # Read targets from STDIN and keep only the public IPs with jq.
  cat targets.txt | scopez -json -silent | jq -r 'select(.type == "ipv4" and .visibility == "Public") | .ipv4'

  # Exclude out-of-scope targets.
  scopez -list targets.txt -exclude-file out-of-scope.txt -table

  # Draw the targets, their DNS chains and IPs as a network graph.
  scopez -list targets.txt -visual -output-file network.png

  # Preview how the targets are parsed without analyzing them.
  scopez -list targets.txt -simulate
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/xcalts/scopez.svg?style=flat
[contributors-url]: https://github.com/xcalts/scopez/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/xcalts/scopez.svg?style=flat
[stars-url]: https://github.com/xcalts/scopez/stargazers
[issues-shield]: https://img.shields.io/github/issues/xcalts/scopez.svg?style=flat
[issues-url]: https://github.com/xcalts/scopez/issues
[license-shield]: https://img.shields.io/github/license/xcalts/scopez.svg?style=flat
[license-url]: https://github.com/xcalts/scopez/blob/master/LICENSE
[python-shield]: https://img.shields.io/badge/Python-black?logo=python
[python-url]: https://www.python.org/
[linux-shield]: https://img.shields.io/badge/Linux-black?logo=linux
[linux-url]: https://www.linux.org/
[macos-shield]: https://img.shields.io/badge/Darwin-black?logo=macos
[macos-url]: https://www.apple.com/
