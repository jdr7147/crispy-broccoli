#!/usr/bin/env python3
"""
sanitize.py — Document sanitizer for security reports and transcripts.

Randomizes IPv4/IPv6 addresses, MAC addresses, people names, and company names.
All substitutions are logged to a companion file as "original :: substitution".

Supported formats:  .txt  .md  .csv  .log  (plain text)
                    .docx               (requires python-docx)
                    .pdf                (requires pymupdf)

Preserved (never replaced):
  - MITRE ATT&CK identifiers  (T1059, T1059.003, TA0002, M1049)
  - APT / threat-actor names   (APT28, Lazarus Group, Fancy Bear, …)
  - Four-digit years           (2021, 2024, …)

Dependencies:
  pip install spacy faker python-docx pymupdf
  python -m spacy download en_core_web_sm

spacy, faker, python-docx, and pymupdf are all optional; the script degrades
gracefully when any of them are absent.
  - Without faker    → built-in word lists are used for random names/companies.
  - Without spacy    → only IPs and MACs are replaced; names/companies are skipped
                       unless --names / --companies are also provided.
  - Without python-docx → .docx files cannot be processed.
  - Without pymupdf     → .pdf files cannot be processed.
"""

import re
import sys
import random
import argparse
from pathlib import Path
from collections import OrderedDict

# ── optional dependencies ─────────────────────────────────────────────────────

try:
    import spacy as _spacy_mod
    _SPACY = True
except ImportError:
    _SPACY = False

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

# ── patterns: what to DETECT & REPLACE ───────────────────────────────────────

_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Covers full 8-group, compressed (::), and common abbreviated forms
_IPV6_RE = re.compile(
    r'(?<![:\w])'                          # not preceded by colon or word char
    r'('
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'          # full
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'                       # trailing ::
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'                       # leading ::
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'      # one :: compressed
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'
    r'|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'
    r'|::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}'            # IPv4-mapped
    r')'
    r'(?![:\w])'
)

_MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')

# ── ORG entity filters (prevent spacy from over-firing on technical text) ─────

# All-caps abbreviations: EDR, SIEM, SOC, TTP, IOC, XDR, etc.
_ABBREV_RE = re.compile(r'^[A-Z]{2,8}s?$')

# Generic terms that spacy commonly misclassifies as ORG in security documents.
_ORG_BLOCKLIST: set[str] = {
    # Document structure
    'document history', 'table of contents', 'executive summary',
    'introduction', 'background', 'overview', 'conclusion', 'appendix',
    'references', 'revision history', 'change log', 'scope', 'purpose',
    # Security concepts & generic phrases
    'tactics and techniques', 'tactics, techniques, and procedures',
    'tactics, techniques', 'indicators of compromise',
    'threat intelligence', 'incident response', 'threat hunting',
    'red team', 'blue team', 'purple team', 'penetration testing',
    'vulnerability assessment', 'attack surface', 'kill chain',
    'security operations', 'security operations center',
    'defense in depth', 'zero trust',
    # Generic organisational words that are not company names
    'management', 'leadership', 'committee', 'department',
    'division', 'unit', 'staff', 'personnel', 'administration',
}

# Technology vendors and product companies that should never be replaced.
# These appear constantly in security reports as tool/platform names, not as
# the organisations whose identity needs protecting.
_TECH_VENDORS: set[str] = {
    # Cybersecurity — endpoint & XDR
    'crowdstrike', 'sentinelone', 'carbon black', 'vmware carbon black',
    'cylance', 'blackberry cylance', 'cortex xdr', 'trend micro',
    'symantec', 'broadcom symantec', 'mcafee', 'trellix', 'eset',
    'kaspersky', 'bitdefender', 'malwarebytes', 'avast', 'avg', 'norton',
    'huntress', 'cybereason', 'darktrace', 'vectra', 'illumio',
    # Cybersecurity — network & firewall
    'palo alto networks', 'palo alto', 'fortinet', 'fortigate',
    'check point', 'checkpoint', 'cisco', 'juniper', 'juniper networks',
    'sonicwall', 'watchguard', 'barracuda', 'zscaler', 'netskope',
    'cloudflare', 'akamai', 'f5', 'imperva',
    # Cybersecurity — SIEM / SOAR / log management
    'splunk', 'ibm qradar', 'qradar', 'microsoft sentinel', 'azure sentinel',
    'logrhythm', 'exabeam', 'securonix', 'elastic', 'elasticsearch',
    'sumo logic', 'alienvault', 'at&t cybersecurity',
    # Cybersecurity — vulnerability management
    'tenable', 'nessus', 'qualys', 'rapid7', 'nexpose', 'insightvm',
    'bitsight', 'securityscorecard',
    # Cybersecurity — threat intel & IR
    'mandiant', 'fireeye', 'recorded future', 'threatconnect',
    'anomali', 'isight', 'secureworks', 'trustwave',
    # Cybersecurity — identity & PAM
    'okta', 'duo', 'ping identity', 'cyberark', 'beyondtrust',
    'thycotic', 'delinea', 'sailpoint', 'saviynt',
    # Cybersecurity — email & web security
    'proofpoint', 'mimecast', 'abnormal security', 'cofense',
    # Cybersecurity — cloud security
    'wiz', 'orca security', 'lacework', 'prisma cloud', 'aqua security',
    'snyk', 'veracode', 'checkmarx', 'sonarqube',
    # Cybersecurity — deception / other
    'attivo', 'guardicore',
    # Major tech — software & cloud
    'microsoft', 'google', 'apple', 'amazon', 'meta', 'facebook',
    'ibm', 'oracle', 'sap', 'salesforce', 'servicenow', 'adobe',
    'slack', 'zoom', 'atlassian', 'jira', 'confluence',
    # Major tech — hardware & infrastructure
    'intel', 'amd', 'nvidia', 'qualcomm', 'arm',
    'dell', 'hp', 'hpe', 'lenovo', 'aruba',
    # Virtualisation & cloud platforms
    'vmware', 'broadcom', 'aws', 'azure', 'gcp', 'google cloud',
    'red hat', 'suse', 'canonical', 'ubuntu', 'debian',
    # Networking & comms
    'arista', 'netscout', 'opengear',
}

def _should_replace_org(entity_text: str) -> bool:
    """Return False for tech vendors, abbreviations, and generic phrases."""
    stripped = entity_text.strip()
    # Skip all-caps abbreviations (EDR, SIEM, SOC, TTPs …)
    if _ABBREV_RE.match(stripped):
        return False
    # MITRE technique names use slash notation: Scheduled Task/Job, etc.
    if '/' in stripped:
        return False
    lower = stripped.lower()
    # Skip known technology vendors and product companies
    if lower in _TECH_VENDORS:
        return False
    # Skip blocklisted generic phrases
    if lower in _ORG_BLOCKLIST:
        return False
    return True

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
    # Years are only excluded from NER replacement, not from IP/MAC replacement.
    # Including years when protecting IPs would cause IPv6 addresses containing
    # year-like substrings (e.g. "2001:db8::") to be skipped incorrectly.
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


def _ner_replace(text: str, sub_map: _SubMap, protected: set,
                 nlp) -> str:
    doc = nlp(text)
    parts, last = [], 0
    for ent in doc.ents:
        if ent.label_ not in ('PERSON', 'ORG'):
            continue
        s, e = ent.start_char, ent.end_char
        if _is_protected(s, e, protected):
            continue
        if ent.label_ == 'ORG' and not _should_replace_org(ent.text):
            continue
        parts.append(text[last:s])
        gen = _rand_person if ent.label_ == 'PERSON' else _rand_company
        parts.append(sub_map.get_or_create(ent.text, gen))
        last = e
    parts.append(text[last:])
    return ''.join(parts)


def _wordlist_replace(text: str, words: list[str], generator,
                      sub_map: _SubMap, protected: set) -> str:
    """Verbatim whole-word replacement from an explicit list (fallback for no-NER mode)."""
    for word in sorted(words, key=len, reverse=True):  # longest-first avoids partial matches
        pattern = re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE)
        text = _regex_replace(text, pattern, generator, sub_map, protected)
        protected = _build_protected(text)
    return text

# ── spacy loader (cached) ─────────────────────────────────────────────────────

_nlp_cache = None

def _load_spacy_model(model: str = 'en_core_web_sm'):
    global _nlp_cache
    if _nlp_cache is None:
        import spacy
        try:
            _nlp_cache = spacy.load(model)
        except OSError:
            raise RuntimeError(
                f'spacy model "{model}" not found.\n'
                f'Run:  python -m spacy download {model}'
            )
    return _nlp_cache

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
        # Sort longest-first so "John Smith" is redacted before "John".
        sorted_pairs = sorted(pairs, key=lambda x: len(x[0]), reverse=True)
        for page in doc:
            for orig, repl in sorted_pairs:
                hits = page.search_for(orig, quads=False)
                for rect in hits:
                    page.add_redact_annot(rect, text=repl,
                                          fontname='helv', fontsize=0,
                                          align=fitz.TEXT_ALIGN_LEFT)
            # images=PDF_REDACT_IMAGE_NONE leaves embedded images untouched.
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
        doc.save(str(out_path), garbage=4, deflate=True)
    finally:
        doc.close()

# ── public API ────────────────────────────────────────────────────────────────

def sanitize(
    text: str,
    *,
    use_ner: bool = True,
    spacy_model: str = 'en_core_web_sm',
    extra_names: list[str] | None = None,
    extra_companies: list[str] | None = None,
) -> tuple[str, list[tuple[str, str]]]:
    """
    Sanitize *text* and return (sanitized_text, substitution_pairs).

    substitution_pairs is a list of (original, replacement) tuples in
    first-seen order.
    """
    sub_map = _SubMap()

    # 1. Regex: IPs then MACs (unambiguous)
    # Years are intentionally excluded from protection here: year-like substrings
    # (e.g. "2001" in an IPv6 address) must not block IP replacement.
    for pattern, gen in [(_IPV4_RE, _rand_ipv4), (_IPV6_RE, _rand_ipv6), (_MAC_RE, _rand_mac)]:
        protected = _build_protected(text, include_years=False)
        text = _regex_replace(text, pattern, gen, sub_map, protected)

    # 2. NER: names and companies (years ARE protected here)
    if use_ner and _SPACY:
        try:
            nlp = _load_spacy_model(spacy_model)
            protected = _build_protected(text, include_years=True)
            text = _ner_replace(text, sub_map, protected, nlp)
        except RuntimeError as exc:
            print(f'[warn] {exc}', file=sys.stderr)

    # 3. Explicit word-list fallback / supplement
    protected = _build_protected(text, include_years=True)
    if extra_names:
        text = _wordlist_replace(text, extra_names, _rand_person, sub_map, protected)
        protected = _build_protected(text, include_years=True)
    if extra_companies:
        text = _wordlist_replace(text, extra_companies, _rand_company, sub_map, protected)

    return text, sub_map.pairs()

# ── CLI ───────────────────────────────────────────────────────────────────────

_PLAIN_TEXT_SUFFIXES = {'.txt', '.md', '.csv', '.log', '.json', '.yaml', '.yml'}

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Sanitize a document: randomize IPs, MACs, names, and companies.',
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
        '--no-ner', action='store_true',
        help='Skip NER-based name/company replacement. Only IPs and MACs are replaced '
             'unless --names or --companies are also provided.',
    )
    parser.add_argument(
        '--spacy-model', default='en_core_web_sm', metavar='MODEL',
        help='spacy model to use for NER (default: en_core_web_sm). '
             'Larger models (en_core_web_md, en_core_web_lg) are more accurate.',
    )
    parser.add_argument(
        '--names', metavar='FILE',
        help='Plain-text file with one person name per line to replace '
             '(used in addition to NER, or as a fallback when --no-ner is set).',
    )
    parser.add_argument(
        '--companies', metavar='FILE',
        help='Plain-text file with one company name per line to replace.',
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        sys.exit(f'Error: file not found: {in_path}')

    suffix = in_path.suffix.lower()
    stem   = in_path.stem
    out_path  = Path(args.output)        if args.output        else in_path.parent / f'{stem}.sanitized{in_path.suffix}'
    subs_path = Path(args.substitutions) if args.substitutions else in_path.parent / f'{stem}.substitutions.txt'

    extra_names:     list[str] = []
    extra_companies: list[str] = []
    if args.names:
        extra_names = [l.strip() for l in Path(args.names).read_text(encoding='utf-8').splitlines() if l.strip()]
    if args.companies:
        extra_companies = [l.strip() for l in Path(args.companies).read_text(encoding='utf-8').splitlines() if l.strip()]

    use_ner = not args.no_ner
    if use_ner and not _SPACY:
        print(
            '[info] spacy is not installed — NER-based name/company replacement is disabled.\n'
            '[info] Only IPs and MACs will be replaced unless you pass --names / --companies.\n'
            '[info] To enable NER:  pip install spacy && python -m spacy download en_core_web_sm',
            file=sys.stderr,
        )

    # ── dispatch by format ────────────────────────────────────────────────────

    if suffix == '.docx':
        if not _DOCX:
            sys.exit('Error: python-docx is required for .docx files.\n'
                     'Install with:  pip install python-docx')
        source_text = _extract_text_docx(in_path)
        _, substitutions = sanitize(
            source_text, use_ner=use_ner, spacy_model=args.spacy_model,
            extra_names=extra_names or None, extra_companies=extra_companies or None,
        )
        _write_sanitized_docx(in_path, out_path, substitutions)

    elif suffix == '.pdf':
        if not _PDF:
            sys.exit('Error: pymupdf is required for .pdf files.\n'
                     'Install with:  pip install pymupdf')
        source_text = _extract_text_pdf(in_path)
        _, substitutions = sanitize(
            source_text, use_ner=use_ner, spacy_model=args.spacy_model,
            extra_names=extra_names or None, extra_companies=extra_companies or None,
        )
        _write_sanitized_pdf(in_path, out_path, substitutions)

    else:
        # Plain text (and any unrecognised extension — treat as UTF-8 text)
        if suffix not in _PLAIN_TEXT_SUFFIXES:
            print(f'[info] Unrecognised extension "{suffix}" — treating as plain text.',
                  file=sys.stderr)
        text = in_path.read_text(encoding='utf-8', errors='replace')
        sanitized, substitutions = sanitize(
            text, use_ner=use_ner, spacy_model=args.spacy_model,
            extra_names=extra_names or None, extra_companies=extra_companies or None,
        )
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
