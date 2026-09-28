# Run the Metasploit Instructor on Kali Linux

This app is an offline command instructor. It does not connect to Metasploit, invoke `msfconsole`, run modules, or capture terminal output. It prepares catalog and module-inspection commands for you to copy into a local Metasploit console.

## Install dependencies

From the project directory:

```bash
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Metasploit Framework must be installed separately on Kali for the console commands to work.

## Start the tools

Open one terminal and start Metasploit:

```bash
msfconsole
```

In another terminal, from the project directory, start the GUI:

```bash
.venv/bin/python app.py
```

Use the Command Instructor to prepare search, module-info, or show-options commands. Copy them into `msfconsole` and review the result there. Output can be pasted back into the app for reference.

The Assessment Report tab lets you record authorized scope and document findings with severity, evidence, and remediation notes. Export the report as Markdown when finished. Report data stays in the app and is not sent to a service.

The Defensive Check Pad prepares two fixed auxiliary inventory workflows: common TCP service ports and an HTTP page-title check. It accepts only loopback or private RFC1918 IPv4 targets, limits a range to 256 addresses, and requires an authorization confirmation. It only prepares commands for review; it does not run them. Confirm the target and options in `msfconsole` before manually running a check.
