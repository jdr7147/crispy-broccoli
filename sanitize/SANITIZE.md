# Document Sanitizer — Setup & Usage Guide

Automatically replaces IP addresses and MAC addresses with random substitutes.
People names and company names are replaced only when you specify them on the
command line — nothing is guessed or inferred.

All substitutions are logged to a companion file so you always know what was
changed.

**Supported file types:** `.txt` `.md` `.csv` `.log` `.docx` `.pdf`

---

## What You Need

| Requirement | Notes |
|---|---|
| Windows 10 or 11 | 64-bit |
| Python 3.10 – 3.12 | 3.13 is **not** recommended (library compatibility) |
| `sanitize.py` | The sanitizer script |
| ~100 MB free disk space | For Python packages |

---

## Step 1 — Install Python

If you already have Python from the transcription tool setup, skip to Step 2.

1. Go to **python.org/downloads** and download Python **3.11** (recommended).
2. Run the installer.
3. On the first screen, check **"Add python.exe to PATH"** before clicking Install.
4. Complete the installation.

Verify it worked — open **Command Prompt** (`Win + R`, type `cmd`, press Enter) and run:

```
python --version
```

You should see something like `Python 3.11.x`.

---

## Step 2 — Set Up a Virtual Environment

> Skip this step if you already have the `C:\venv` environment from the transcription tool.

In Command Prompt, run:

```
python -m venv C:\venv
```

Then activate it:

```
C:\venv\Scripts\activate
```

Your prompt should now start with `(venv)`. You must activate this every time
you open a new Command Prompt window before running the tool.

---

## Step 3 — Install Required Packages

With the environment activated, run:

```
pip install faker python-docx pymupdf
```

### What each package does

| Package | Purpose | Required? |
|---|---|---|
| `faker` | Generates realistic-sounding fake names and companies | Optional |
| `python-docx` | Reads and writes `.docx` Word files | Only for `.docx` files |
| `pymupdf` | Reads and writes `.pdf` files | Only for `.pdf` files |

> Without `faker`, the tool uses short built-in word lists to generate
> replacements. The results are less realistic but functionally identical.

---

## Step 4 — Download the Script

Save `sanitize.py` to a folder you'll remember, for example:

```
C:\Users\YourName\Downloads\sanitize.py
```

---

## Step 5 — Run the Tool

Open Command Prompt, activate the virtual environment, then navigate to the
folder containing the script:

```
C:\venv\Scripts\activate
cd C:\Users\YourName\Downloads
```

### IPs and MACs only (no names specified)

```
python sanitize.py report.txt
```

All IP addresses and MAC addresses are replaced automatically. Nothing else
is touched.

### Replacing people names

```
python sanitize.py report.txt --names "John Smith" "Jane Doe"
```

### Replacing company names

```
python sanitize.py report.txt --companies "Acme Corp" "North Carolina Farm Bureau"
```

### Both at once

```
python sanitize.py report.txt --names "John Smith" "Jane Doe" --companies "Acme Corp"
```

### Word documents (.docx)

```
python sanitize.py incident_report.docx --names "John Smith" --companies "Acme Corp"
```

Produces `incident_report.sanitized.docx` with formatting, tables, and layout
preserved.

### PDF documents (.pdf)

```
python sanitize.py threat_brief.pdf --companies "North Carolina Farm Bureau"
```

Produces `threat_brief.sanitized.pdf` with the layout and images preserved.

---

## Output Files

Given `report.txt`, the tool produces two files in the same folder:

| File | Contents |
|---|---|
| `report.sanitized.txt` | The cleaned document — safe to share |
| `report.substitutions.txt` | Log of every replacement made |

The original `report.txt` is **never modified**.

---

## What Gets Replaced

| Content | Replaced automatically? | How to replace |
|---|---|---|
| IPv4 address | Yes | — |
| IPv6 address | Yes | — |
| MAC address | Yes | — |
| Person name | No | `--names "First Last"` |
| Company name | No | `--companies "Company Name"` |

## What Is Never Replaced

| Content | Examples |
|---|---|
| MITRE ATT&CK techniques & tactics | `T1059`, `T1059.003`, `TA0002`, `M1049` |
| APT / threat-actor names | `APT28`, `Fancy Bear`, `Lazarus Group`, `Volt Typhoon` |
| Four-digit years | `2021`, `2024` |

---

## Substitutions Log

Every replacement is recorded in `<filename>.substitutions.txt`, one per line:

```
203.0.113.42 :: 156.78.201.34
00:1A:2B:3C:4D:5E :: fe:ca:2e:2f:46:bd
John Smith :: Alex Anderson
North Carolina Farm Bureau :: Premier Consulting
```

The same original value always maps to the same replacement within a single
run — so if `John Smith` appears ten times in a document, every occurrence
becomes the same fake name.

`The North Carolina Farm Bureau` and `North Carolina Farm Bureau` are treated
as the same entity and receive the same substitution.

---

## All Available Options

| Option | Description |
|---|---|
| `input` | Path to the file to sanitize. |
| `-o PATH` | Custom path for the sanitized output file. |
| `-s PATH` | Custom path for the substitutions log. |
| `--names NAME [NAME ...]` | One or more person names to replace. |
| `--companies COMPANY [COMPANY ...]` | One or more company names to replace. |
| `--names-file FILE` | Plain-text file with one name per line (combined with `--names`). |
| `--companies-file FILE` | Plain-text file with one company per line (combined with `--companies`). |

---

## Using List Files for Long Name Lists

If you have many names or companies to replace, put them in a plain-text file
with one entry per line instead of listing them all on the command line.

**`names.txt`**
```
John Smith
Jane Doe
Robert Johnson
```

**`companies.txt`**
```
North Carolina Farm Bureau
Acme Corporation
Initech
```

Then run:

```
python sanitize.py report.txt --names-file names.txt --companies-file companies.txt
```

You can combine file and inline values at the same time:

```
python sanitize.py report.txt --names "Jane Doe" --names-file more_names.txt
```

---

## Examples

Sanitize a plain-text transcript, saving output to a specific folder:

```
python sanitize.py transcript.txt -o C:\Sanitized\transcript_clean.txt
```

Sanitize a Word document with several names and a company:

```
python sanitize.py incident.docx --names "John Smith" "Jane Doe" --companies "Acme Corp"
```

Sanitize a PDF using a pre-built name list:

```
python sanitize.py threat_intel.pdf --names-file names.txt --companies-file companies.txt
```

Sanitize for IPs and MACs only, with a custom substitutions log location:

```
python sanitize.py report.txt -s C:\Logs\report_subs.txt
```

---

## Troubleshooting

**"python-docx is required for .docx files"**
Run `pip install python-docx` with the virtual environment active.

**"pymupdf is required for .pdf files"**
Run `pip install pymupdf` with the virtual environment active.

**A name is not being replaced**
Check that the name is spelled and capitalised exactly as it appears in the
document. The match is case-insensitive but the word boundaries must align —
`John` will not match `Johnson`.

**PDF output text looks different from the original**
PDF redaction replaces text in-place using a standard font (Helvetica). If the
replacement is significantly longer than the original, it may run slightly
beyond the original bounding box. This is a known limitation of in-place PDF
redaction.
