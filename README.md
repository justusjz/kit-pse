# KIT PSE: Intrusion Detection using Machine Learning

## Code

The system is written completely in Python, using the
[Scapy library](https://scapy.net/). We're using the
[uv package manager](https://github.com/astral-sh/uv) for managing our Python
installation and dependencies. This automatically installs everything that's
required, to run the code you just have to do:

```bash
sudo uv run src/main.py
```

Note that `sudo` (on Linux systems) is required because the packet inspection
done by Scapy requires root permissions. On Windows, you probably have to run
the Python script using administrator permissions.

## Tests

To run tests, simply do:

```bash
uv run test.py
```

in the root directory.

## Reports

All reports are written using LaTeX, and can be found in the `reports`
subdirectory. To build the files, you can either use
[Overleaf](https://overleaf.com), or install the following dependencies:

- texlive-basic
- texlive-fontsextra
- texlive-langgerman
- texlive-latex
- texlive-latexrecommended
- texlive-latexextra
- texlive-plaingeneric

To build the reports, run:

```bash
make
```

You might have to run this command twice to get the table of contents right.
