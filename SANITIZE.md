# Document Sanitizer — Setup & Usage Guide

Replaces sensitive details in security reports and transcripts — IP addresses,
MAC addresses, people names, and company names — with random substitutes,
while leaving technical content (MITRE techniques, APT group names, years)
untouched. Every replacement is logged to a companion file so you always know
what was changed.

**Supported file types:** `.txt` `.md` `.csv` `.log` `.docx` `.pdf`

---

## What You Need

| Requirement | Notes |
|---|---|
| Windows 10 or 11 | 64-bit |
| Python 3.10 – 3.12 | 3.13 is **not** recommended (library compatibility) |
| `sanitize.py` | The sanitizer script |
| ~500 MB free disk space | For Python packages and the spacy language model |

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
pip install spacy faker python-docx pymupdf
```

Then download the English language model that spacy uses to recognise names and
company names:

```
python -m spacy download en_core_web_sm
```

### What each package does

| Package | Purpose | Required? |
|---|---|---|
| `spacy` + `en_core_web_sm` | Detects people names and company names using AI | Recommended |
| `faker` | Generates realistic-sounding fake names and companies | Optional |
| `python-docx` | Reads and writes `.docx` Word files | Only for `.docx` files |
| `pymupdf` | Reads and writes `.pdf` files | Only for `.pdf` files |

> If you skip `spacy`, only IP addresses and MAC addresses will be replaced.
> Names and company names will be left untouched unless you supply them manually
> with `--names` or `--companies` (see Advanced Options below).

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

### Basic usage

```
python sanitize.py my_report.txt
```

This produces two files in the same folder:

| File | Contents |
|---|---|
| `my_report.sanitized.txt` | The cleaned document — safe to share |
| `my_report.substitutions.txt` | Log of every replacement made |

The original `my_report.txt` is **never modified**.

### Word documents (.docx)

```
python sanitize.py incident_report.docx
```

Produces `incident_report.sanitized.docx` with formatting, tables, and layout
preserved.

### PDF documents (.pdf)

```
python sanitize.py threat_brief.pdf
```

Produces `threat_brief.sanitized.pdf` with the layout and images preserved.
Replaced text is rendered in-place using a standard font.

---

## What Gets Replaced

| Content | Example original | Example replacement |
|---|---|---|
| IPv4 address | `203.0.113.42` | `156.78.201.34` |
| IPv6 address | `2001:db8::1` | `af86:0903::7334` |
| MAC address | `00:1A:2B:3C:4D:5E` | `fe:ca:2e:2f:46:bd` |
| Person name | `John Smith` | `Alex Anderson` |
| Company name | `Acme Corporation` | `Nexus Solutions` |

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
Acme Corporation :: Nexus Solutions
```

The same original value always maps to the same replacement within a single
run — so if `John Smith` appears ten times in a document, every occurrence
becomes the same fake name.

---

## All Available Options

| Option | Default | Description |
|---|---|---|
| `input` | *(required)* | Path to the file to sanitize. |
| `-o PATH` | `<input>.sanitized<ext>` | Custom path for the sanitized output file. |
| `-s PATH` | `<input>.substitutions.txt` | Custom path for the substitutions log. |
| `--no-ner` | — | Skip AI name/company detection. Only IPs and MACs are replaced (much faster). |
| `--spacy-model MODEL` | `en_core_web_sm` | Use a larger, more accurate spacy model. See note below. |
| `--names FILE` | — | Plain-text file listing person names to replace, one per line. |
| `--companies FILE` | — | Plain-text file listing company names to replace, one per line. |

### Choosing a spacy model

| Model | Size | Accuracy | Install command |
|---|---|---|---|
| `en_core_web_sm` | ~12 MB | Good | `python -m spacy download en_core_web_sm` |
| `en_core_web_md` | ~43 MB | Better | `python -m spacy download en_core_web_md` |
| `en_core_web_lg` | ~741 MB | Best | `python -m spacy download en_core_web_lg` |

Use the larger models if names or companies are being missed.

---

## Advanced: Supplying Name Lists Manually

If spacy misses a specific name or company — or if you are not using spacy at
all — you can supply explicit lists.

Create a plain-text file with one entry per line:

**`names.txt`**
```
Jane Doe
Robert Johnson
```

**`companies.txt`**
```
Acme Corporation
Initech
```

Then run:

```
python sanitize.py report.txt --names names.txt --companies companies.txt
```

These lists work alongside NER (not instead of it) unless `--no-ner` is also
passed.

---

## Examples

Sanitize a plain-text transcript, saving output to a specific folder:

```
python sanitize.py transcript.txt -o C:\Sanitized\transcript_clean.txt
```

Sanitize a Word document with a more accurate spacy model:

```
python sanitize.py incident.docx --spacy-model en_core_web_lg
```

Sanitize a PDF without NER (IPs and MACs only, fastest):

```
python sanitize.py threat_intel.pdf --no-ner
```

Sanitize a report and keep the substitutions log in a specific location:

```
python sanitize.py report.txt -s C:\Logs\report_subs.txt
```

---

## Troubleshooting

**"No module named 'spacy'" or similar**
The virtual environment is not active. Run `C:\venv\Scripts\activate` first.

**"spacy model not found"**
Run `python -m spacy download en_core_web_sm` with the virtual environment active.

**"python-docx is required for .docx files"**
Run `pip install python-docx` with the virtual environment active.

**"pymupdf is required for .pdf files"**
Run `pip install pymupdf` with the virtual environment active.

**Names or companies are not being replaced**
Try a larger spacy model (`--spacy-model en_core_web_lg`), or add the missed
names/companies to a text file and pass it with `--names` / `--companies`.

**A MITRE technique or APT name was accidentally replaced**
The built-in preserve list covers common identifiers and named groups. If
something specific is being caught, add it to the `--companies` list with a
matching replacement, or open an issue so it can be added to the preserve list.

**PDF output text looks different from the original**
PDF redaction replaces text in-place using a standard font (Helvetica). If the
replacement is significantly longer than the original, it may run slightly
beyond the original bounding box. This is a known limitation of in-place PDF
redaction.
