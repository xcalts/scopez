<a id="readme-top"></a>

<!-- PROJECT LOGO -->
<br />

<div align="center">

[![Python][python-shield]][python-url]
[![Stars][stars-shield]][stars-url]
[![Contributors][contributors-shield]][contributors-url]
[![Lint][lint-shield]][lint-url]
[![Issues][issues-shield]][issues-url]

  <a href="https://github.com/xcalts/scopez">
    <img src="https://github.com/xcalts/scopez/raw/main/.github/logo.svg" alt="Logo" height="100" />
  </a>
  <p align="center">
    Scopez verifies connectivity to target servers, reveals CDN presence, and provides detailed target insights like reachability and RDAP.
    <br />
    <br />
    !! It does not run properly in Windows !!
    <br />
    <br />
    <a href="https://github.com/xcalts/scopez/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/xcalts/scopez/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
    ·
    <a href="https://pypi.org/project/scopez/">PyPI</a>
  </p>

<img src="https://github.com/xcalts/scopez/raw/main/.github/usage.png" />

</div>

## Features

- Parses a file filled with targets
- Does IP networks **math**
- Captures **RDAP** data
- **Pings** IPs and FQDNs
- Displays **DNS chains**
- Unix friendly input/output
- **Threads** support
- Multiple input support - **STDIN/FILE/CIDR/IP/FQDN/URL**
- Multiple output support - **TABLE/JSON/TXT/STDOUT**

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## TODOs

- Input support - **IP with port, FQDN with port**
- **Proxies** support for URL probing
- **Markdown** output
- **Configuration** YAML file

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Installation

You can install `scopez` using `pip`.

```
pip install scopez
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

```
Usage: scopez [OPTIONS]

DEBUG:
  -version   Show the version and exit.
  -no-color  Disable colors in CLI output.
  -silent    Display only results in output.
  -simulate  Display the parsed targets.

INPUT:
  -target           Targets to analyze (comma-separated).
  -list             List of targets to analyze (file).
  -exclude-targets  Targets to exclude from analysis (comma-separated).
  -exclude-file     List of targets to exclude from analysis (file).

OUTPUT:
  -json   Write output in JSON lines format.
  -table  Write output in Table format.

TWEAK:
  -threads  The max number of worker threads.

OTHER:
  -help  Show this message and exit.
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Developing

In order to start developing you will need to to follow the instructions below.

```txt
> pyenv install 3.12.6
> pyenv global 3.12.6
> python3 -m venv .venv
> source .venv/bin/activate
> (.venv) pip install ruff pre-commit
> (.venv) pip install -e .
> (.venv) scopez --version
> (.venv) ruff check --fix
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Building Standalones

Follow the instructions below to build a standalone `scopez` executable.

> Note: currently only `elf` standalone executables are supported.

**Linux**

```txt
> python3 -m venv .venv
> source .venv/bin/activate
> (.venv) pip install -e .
> (.venv) pip install --upgrade cx_Freeze
> (.venv) python3 setup_cx.py build
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Dependencies

- [click](https://github.com/pallets/click)
- [requests](https://github.com/psf/requests)
- [rich](https://github.com/Textualize/rich)
- [pydantic](https://github.com/pydantic/pydantic)
- [ipwhois](https://github.com/secynic/ipwhois)
- [fqdn](https://github.com/ypcrts/fqdn)
- [cx_Freeze](https://github.com/marcelotduarte/cx_Freeze)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Inspirations

- [naabu](https://github.com/projectdiscovery/naabu)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contributing

Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request.
You can also simply open an issue with the tag "enhancement".

1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the Branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/xcalts/scopez.svg?style=flat
[contributors-url]: https://github.com/xcalts/scopez/graphs/contributors
[lint-shield]: https://img.shields.io/github/actions/workflow/status/xcalts/scopez/ruff.yml?style=flat&label=ruff
[lint-url]: https://github.com/xcalts/scopez/actions/workflows/ruff.yml
[stars-shield]: https://img.shields.io/github/stars/xcalts/scopez.svg?style=flat
[stars-url]: https://github.com/xcalts/scopez/stargazers
[issues-shield]: https://img.shields.io/github/issues/xcalts/scopez.svg?style=flat
[issues-url]: https://github.com/xcalts/scopez/issues
[license-shield]: https://img.shields.io/github/license/xcalts/scopez.svg?style=flat
[license-url]: https://github.com/xcalts/scopez/blob/master/LICENSE
[python-shield]: https://img.shields.io/badge/-python-black?style=flat
[python-url]: https://www.python.org/
