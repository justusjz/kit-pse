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
uv run -m unittest discover src
```

or

```bash
python -m unittest discover src
```

in the root directory. The tests do not need root permissions, since they don't
actually send any packets over the network interface, they just call the handler
directly.

## Run and Debug Code in IDE

To run the python script on Linux without permission problem and to have
possibility to debug the code using IDE functions you should give python
interpreter the privileges to run scripts in sudo mode. Run this command inside
your directory:

WARNING: Running this is equivalent to allowing `sudo` without a password, so it
gives every program you run root permissions. While this may be justifiable in a
development environment, it's still a major security risk. Consider your threat
model and use best judgment.

```bash
sudo chmod +s .venv/bin/python
```

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
