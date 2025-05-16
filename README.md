<a id="readme-top"></a>

<!-- PROJECT LOGO -->
<br />

<div align="center">
  <a href="https://github.com/xcalts/scopez">
    <img src=".github/logo.png" alt="Logo" height="100" />
  </a>
  <h3 align="center">scopez</h3>
  <p align="center">
    Scopez is a targets analyzer tool written in python with a focus in simplicity.
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

- Optimized for ease of use and lightweight on resources
- Parsing a file filled with targets
- Multiple input support - **STDIN/FILE/HOST/IP/URL**
- Multiple output support - **JSON/TXT/STDOUT**

## Developing

In order to start developing you will need to to follow the instructions below.

```txt
> pyenv install 3.12.6
> pyenv global 3.12.6
> python3 -m venv .venv
> source .venv/bin/activate
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
