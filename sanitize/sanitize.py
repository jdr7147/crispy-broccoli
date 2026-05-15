#!/usr/bin/env python3
"""
sanitize.py — Document sanitizer for security reports and transcripts.

Automatically replaces IPv4/IPv6 addresses and MAC addresses with random
substitutes.  People names and company names are replaced only when you
explicitly specify them on the command line.

All substitutions are logged to a companion file as "original :: substitution".

Supported formats:  .txt  .md  .csv  .log  and any plain-text file
                    .docx  (requires python-docx)
                    .pdf   (requires pymupdf)

Preserved (never replaced):
  - MITRE ATT&CK identifiers  (T1059, T1059.003, TA0002, M1049)
  - APT / threat-actor names   (APT28, Lazarus Group, Fancy Bear, …)
  - Four-digit years           (2021, 2024, …)

Usage examples:
  python sanitize.py report.txt
  python sanitize.py report.txt --names "John Smith" "Jane Doe"
  python sanitize.py report.txt --companies "Acme Corp" "North Carolina Farm Bureau"
  python sanitize.py report.txt --names "John Smith" --companies "Acme Corp" --names-file more_names.txt
  python sanitize.py report.docx -o clean_report.docx

Dependencies (all optional):
  pip install faker python-docx pymupdf
  - Without faker      → built-in word lists generate replacement names/companies.
  - Without python-docx → .docx files cannot be processed.
  - Without pymupdf    → .pdf files cannot be processed.
"""

import re
import sys
import random
import argparse
from pathlib import Path
from collections import OrderedDict

# ── optional dependencies ─────────────────────────────────────────────────────

try:
    from faker import Faker as _Faker
    _fake = _Faker()
    _FAKER = True
except ImportError:
    _FAKER = False

try:
    import docx as _docx_mod          # python-docx
    _DOCX = True
except ImportError:
    _DOCX = False

try:
    import fitz as _fitz_mod          # PyMuPDF
    _PDF = True
except ImportError:
    _PDF = False

# ── patterns: what to PRESERVE ───────────────────────────────────────────────

# MITRE ATT&CK: T1059, T1059.003, TA0002, M1049
_MITRE_RE = re.compile(r'\b(?:T[A]?\d{4}(?:\.\d{3})?|M\d{4})\b')

# Known threat-actor / APT naming conventions + a broad list of named groups
_APT_NAMES = '|'.join([
    r'APT\s*\d+',
    r'FIN\d+',
    r'UNC\d+',
    r'Lazarus(?:\s+Group)?',
    r'Fancy\s+Bear',
    r'Cozy\s+Bear',
    r'Sandworm(?:\s+Team)?',
    r'Turla',
    r'Equation\s+Group',
    r'Carbanak',
    r'Cobalt\s+(?:Group|Strike\s+(?:group|team))',
    r'DarkSide',
    r'REvil',
    r'Conti',
    r'BlackCat',
    r'LockBit',
    r'Cl0p',
    r'Hive',
    r'Scattered\s+Spider',
    r'Lapsus\$?',
    r'Volt\s+Typhoon',
    r'Salt\s+Typhoon',
    r'Silk\s+Typhoon',
    r'Midnight\s+Blizzard',
    r'Forest\s+Blizzard',
    r'Comet\s+Tempest',
])
_APT_RE = re.compile(r'\b(?:' + _APT_NAMES + r')\b', re.IGNORECASE)

# Four-digit years 1900–2099
_YEAR_RE = re.compile(r'\b(?:19|20)\d{2}\b')

# ── patterns: what to AUTO-DETECT & REPLACE ──────────────────────────────────

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Covers full 8-group, compressed (::), and common abbreviated forms
_IPV6_RE = re.compile(
    r'(?<![:\w])'
    r'('
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'
    r'|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'
    r'|::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}'
    r')'
    r'(?![:\w])'
)

_MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')

# ── fallback word lists (used when faker is not installed) ────────────────────

_FIRST_NAMES = [
    'Alex', 'Jordan', 'Morgan', 'Taylor', 'Casey', 'Riley', 'Drew',
    'Sam', 'Jamie', 'Chris', 'Robin', 'Dana', 'Blake', 'Avery', 'Quinn',
]
_LAST_NAMES = [
    'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Davis', 'Miller',
    'Wilson', 'Moore', 'Anderson', 'Thomas', 'Jackson', 'White', 'Harris',
]
_COMPANY_ADJ = [
    'Global', 'Advanced', 'Secure', 'Digital', 'Integrated', 'Strategic',
    'United', 'Premier', 'Dynamic', 'Apex', 'Vertex', 'Core', 'Nexus',
]
_COMPANY_NOUN = [
    'Systems', 'Solutions', 'Technologies', 'Group', 'Services', 'Networks',
    'Dynamics', 'Industries', 'Consulting', 'Partners', 'Holdings', 'Labs',
]

# ── replacement generators ────────────────────────────────────────────────────

def _rand_ipv4() -> str:
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

def _rand_ipv6() -> str:
    return ':'.join(format(random.randint(0, 0xFFFF), '04x') for _ in range(8))

def _rand_mac() -> str:
    return ':'.join(format(random.randint(0, 255), '02x') for _ in range(6))

def _rand_person() -> str:
    if _FAKER:
        return _fake.name()
    return f'{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}'

def _rand_company() -> str:
    if _FAKER:
        return _fake.company()
    return f'{random.choice(_COMPANY_ADJ)} {random.choice(_COMPANY_NOUN)}'

# ── substitution map ──────────────────────────────────────────────────────────

# Leading articles are stripped before keying so "The Acme Corp" and "Acme Corp"
# resolve to the same substitution.
_ARTICLE_RE = re.compile(r'^\s*(?:the|an?)\s+', re.IGNORECASE)

class _SubMap:
    """Tracks original→substitution pairs, deduplicating case-insensitively."""

    def __init__(self):
        self._map: OrderedDict[str, tuple[str, str]] = OrderedDict()

    def get_or_create(self, original: str, generator) -> str:
        key = _ARTICLE_RE.sub('', original).lower().strip()
        if key not in self._map:
            self._map[key] = (original, generator())
        return self._map[key][1]

    def pairs(self) -> list[tuple[str, str]]:
        return list(self._map.values())

# ── protected-span helpers ────────────────────────────────────────────────────

def _build_protected(text: str, include_years: bool = True) -> set[tuple[int, int]]:
    # Years are excluded when protecting IPs: year-like substrings inside IPv6
    # addresses (e.g. "2001" in 2001:db8::) must not block IP replacement.
    patterns = [_MITRE_RE, _APT_RE]
    if include_years:
        patterns.append(_YEAR_RE)
    spans: set[tuple[int, int]] = set()
    for pattern in patterns:
        for m in pattern.finditer(text):
            spans.add((m.start(), m.end()))
    return spans

def _is_protected(start: int, end: int, protected: set) -> bool:
    return any(s < end and start < e for s, e in protected)

# ── core replacement routines ─────────────────────────────────────────────────

def _regex_replace(text: str, pattern: re.Pattern, generator,
                   sub_map: _SubMap, protected: set) -> str:
    parts, last = [], 0
    for m in pattern.finditer(text):
        s, e = m.start(), m.end()
        parts.append(text[last:s])
        if _is_protected(s, e, protected):
            parts.append(m.group())
        else:
            parts.append(sub_map.get_or_create(m.group(), generator))
        last = e
    parts.append(text[last:])
    return ''.join(parts)


def _wordlist_replace(text: str, words: list[str], generator,
                      sub_map: _SubMap, protected: set) -> str:
    """Whole-word, case-insensitive replacement for an explicit list of terms."""
    for word in sorted(words, key=len, reverse=True):  # longest-first avoids partial matches
        pattern = re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE)
        text = _regex_replace(text, pattern, generator, sub_map, protected)
        protected = _build_protected(text, include_years=True)
    return text

# ── apply-back helper (used for docx runs and pdf pages) ─────────────────────

def _apply_substitutions(text: str, pairs: list[tuple[str, str]]) -> str:
    """Apply substitution pairs to a text fragment, longest match first."""
    for orig, repl in sorted(pairs, key=lambda x: len(x[0]), reverse=True):
        text = re.sub(re.escape(orig), repl, text, flags=re.IGNORECASE)
    return text

# ── docx support ──────────────────────────────────────────────────────────────

def _iter_docx_paragraphs(doc):
    """Yield every paragraph in a docx document: body, tables, headers, footers."""
    yield from doc.paragraphs
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                yield from cell.paragraphs
    for section in doc.sections:
        yield from section.header.paragraphs
        yield from section.footer.paragraphs

def _extract_text_docx(path: Path) -> str:
    import docx
    doc = docx.Document(str(path))
    return '\n'.join(p.text for p in _iter_docx_paragraphs(doc))

def _write_sanitized_docx(in_path: Path, out_path: Path,
                           pairs: list[tuple[str, str]]) -> None:
    import docx
    doc = docx.Document(str(in_path))
    for para in _iter_docx_paragraphs(doc):
        for run in para.runs:
            if run.text:
                run.text = _apply_substitutions(run.text, pairs)
    doc.save(str(out_path))

# ── pdf support ───────────────────────────────────────────────────────────────

def _extract_text_pdf(path: Path) -> str:
    import fitz
    doc = fitz.open(str(path))
    try:
        return '\n'.join(page.get_text() for page in doc)
    finally:
        doc.close()

def _write_sanitized_pdf(in_path: Path, out_path: Path,
                          pairs: list[tuple[str, str]]) -> None:
    import fitz
    doc = fitz.open(str(in_path))
    try:
        sorted_pairs = sorted(pairs, key=lambda x: len(x[0]), reverse=True)
        for page in doc:
            for orig, repl in sorted_pairs:
                hits = page.search_for(orig, quads=False)
                for rect in hits:
                    page.add_redact_annot(rect, text=repl,
                                          fontname='helv', fontsize=0,
                                          align=fitz.TEXT_ALIGN_LEFT)
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
        doc.save(str(out_path), garbage=4, deflate=True)
    finally:
        doc.close()

# ── public API ────────────────────────────────────────────────────────────────

def sanitize(
    text: str,
    *,
    names: list[str] | None = None,
    companies: list[str] | None = None,
) -> tuple[str, list[tuple[str, str]]]:
    """
    Sanitize *text* and return (sanitized_text, substitution_pairs).

    IPs and MACs are always replaced automatically.  Names and companies are
    only replaced when explicitly provided.
    """
    sub_map = _SubMap()

    # 1. IPs and MACs — auto-detected, years not protected here to avoid
    #    blocking IPv6 addresses that contain year-like substrings (e.g. 2001:db8::)
    for pattern, gen in [(_IPV4_RE, _rand_ipv4), (_IPV6_RE, _rand_ipv6), (_MAC_RE, _rand_mac)]:
        protected = _build_protected(text, include_years=False)
        text = _regex_replace(text, pattern, gen, sub_map, protected)

    # 2. Explicit proper nouns — years ARE protected here
    protected = _build_protected(text, include_years=True)
    if names:
        text = _wordlist_replace(text, names, _rand_person, sub_map, protected)
        protected = _build_protected(text, include_years=True)
    if companies:
        text = _wordlist_replace(text, companies, _rand_company, sub_map, protected)

    return text, sub_map.pairs()

# ── CLI ───────────────────────────────────────────────────────────────────────

_PLAIN_TEXT_SUFFIXES = {'.txt', '.md', '.csv', '.log', '.json', '.yaml', '.yml'}

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            'Sanitize a document. IPs and MACs are replaced automatically. '
            'Names and companies are replaced only when specified.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('input', help='Path to the document to sanitize.')
    parser.add_argument(
        '-o', '--output',
        help='Output path (default: <input>.sanitized<ext>).',
    )
    parser.add_argument(
        '-s', '--substitutions',
        help='Substitutions log path (default: <input>.substitutions.txt).',
    )
    parser.add_argument(
        '--names', nargs='+', metavar='NAME', default=[],
        help='Person name(s) to replace. Repeat or space-separate multiple values. '
             'Example: --names "John Smith" "Jane Doe"',
    )
    parser.add_argument(
        '--companies', nargs='+', metavar='COMPANY', default=[],
        help='Company name(s) to replace. '
             'Example: --companies "Acme Corp" "North Carolina Farm Bureau"',
    )
    parser.add_argument(
        '--names-file', metavar='FILE',
        help='Plain-text file with one person name per line (combined with --names).',
    )
    parser.add_argument(
        '--companies-file', metavar='FILE',
        help='Plain-text file with one company name per line (combined with --companies).',
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        sys.exit(f'Error: file not found: {in_path}')

    suffix = in_path.suffix.lower()
    out_path  = Path(args.output)        if args.output        else in_path.parent / f'{in_path.stem}.sanitized{in_path.suffix}'
    subs_path = Path(args.substitutions) if args.substitutions else in_path.parent / f'{in_path.stem}.substitutions.txt'

    names:     list[str] = list(args.names)
    companies: list[str] = list(args.companies)

    if args.names_file:
        names += [l.strip() for l in Path(args.names_file).read_text(encoding='utf-8').splitlines() if l.strip()]
    if args.companies_file:
        companies += [l.strip() for l in Path(args.companies_file).read_text(encoding='utf-8').splitlines() if l.strip()]

    # ── dispatch by format ────────────────────────────────────────────────────

    if suffix == '.docx':
        if not _DOCX:
            sys.exit('Error: python-docx is required for .docx files.\n'
                     'Install with:  pip install python-docx')
        source_text = _extract_text_docx(in_path)
        _, substitutions = sanitize(source_text, names=names or None, companies=companies or None)
        _write_sanitized_docx(in_path, out_path, substitutions)

    elif suffix == '.pdf':
        if not _PDF:
            sys.exit('Error: pymupdf is required for .pdf files.\n'
                     'Install with:  pip install pymupdf')
        source_text = _extract_text_pdf(in_path)
        _, substitutions = sanitize(source_text, names=names or None, companies=companies or None)
        _write_sanitized_pdf(in_path, out_path, substitutions)

    else:
        if suffix not in _PLAIN_TEXT_SUFFIXES:
            print(f'[info] Unrecognised extension "{suffix}" — treating as plain text.',
                  file=sys.stderr)
        text = in_path.read_text(encoding='utf-8', errors='replace')
        sanitized, substitutions = sanitize(text, names=names or None, companies=companies or None)
        out_path.write_text(sanitized, encoding='utf-8')

    print(f'Sanitized document → {out_path}')

    if substitutions:
        lines = [f'{orig} :: {sub}' for orig, sub in substitutions]
        subs_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        print(f'Substitutions log  → {subs_path}  ({len(lines)} replacement(s))')
    else:
        print('No substitutions were made.')


if __name__ == '__main__':
    main()
