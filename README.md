<a id="readme-top"></a>

<!-- PROJECT LOGO -->
<br />

<div align="center">
  <a href="https://github.com/xcalts/scopez">
    <img src=".github/logo.svg" alt="Logo" height="100" />
  </a>
  <p align="center">
    Scopez is a Python-based target analysis tool built with simplicity in mind.
    <br />
    <a href="https://github.com/xcalts/scopez"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/xcalts/scopez/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    ·
    <a href="https://github.com/xcalts/scopez/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

## Features

- Parses a file filled with targets
- Does IP networks **math**
- Captures **RDAP** data
- **Pings** IPs and FQDNs
- Displays **DNS chains**
- Multiple input support - **STDIN/FILE/CIDR/IP/FQDN/URL**
- Multiple output support - **TABLE/JSON/TXT/STDOUT**

## Usage

```
Usage: scopez [OPTIONS]

DEBUG:
  -version   Show the version and exit.
  -no-color  Disable colors in CLI output.
  -silent    Display only results in output.

INPUT:
  -target           Targets to analyze (comma-separated).
  -list             List of targets to analyze (file).
  -exclude-targets  Targets to exclude from analysis (comma-separated).
  -exclude-file     List of targets to exclude from analysis (file).

OUTPUT:
  -output  File to write output to (optional).
  -json    Write output in JSON lines format.
  -table   Write output in Table format.

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
