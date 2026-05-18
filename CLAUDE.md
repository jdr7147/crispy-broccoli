# Project Guidelines

## Documentation

Every code change must include a documentation update if it affects any of the following:

- Setup requirements or compatibility (Python version, OS support, dependencies)
- CLI options or arguments
- Behaviour visible to the user (new features, changed defaults, removed functionality)
- File structure or tool organisation

The relevant doc files are:

| Tool | Doc file |
|---|---|
| Traffic generator | `traffic-generator/SETUP.md` |
| Meeting transcription | `transcribe/SETUP.md` |
| Document sanitizer | `sanitize/SANITIZE.md` |
| Repo overview | `README.md` |

Documentation updates go in the same commit as the code change.

## Repository Layout

```
transcribe/          Meeting transcription tool (Whisper, Windows)
traffic-generator/   SentinelOne endpoint traffic simulator (cross-platform)
sanitize/            Document sanitization script (Windows)
```

## Python Compatibility

All scripts must run on Python 3.7 and later. Use `from __future__ import annotations`
in any file that uses modern type hint syntax (`X | Y`, `list[str]`, `tuple[...]`, etc.).
