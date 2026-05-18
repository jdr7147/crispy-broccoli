# crispy-broccoli

A collection of security and productivity tools.

---

## Tools

### `transcribe/` — Meeting Transcription Tool

Records microphone and system audio, transcribes locally using OpenAI Whisper
(nothing leaves your machine), and optionally labels each speaker.

- No cloud processing — fully offline
- Optional speaker diarization (Person A, Person B, …)
- Configurable word hints for names and technical terms

**Platform:** Windows  
**Setup:** [transcribe/SETUP.md](transcribe/SETUP.md)

---

### `traffic-generator/` — SentinelOne Traffic Generator

Simulates realistic endpoint activity for validating SentinelOne agent detection
coverage. Mixes normal background traffic with clearly labeled attack simulations.

- OS-aware: automatically loads platform-appropriate attacks
- Normal traffic: web browsing, DNS, SMTP probes, file I/O
- Attack simulations: EICAR, recon bursts, encoded commands, credential access,
  persistence attempts, C2-like connections, and more

**Platform:** Windows · RHEL/CentOS · Debian/Kali · macOS  
**Setup:** [traffic-generator/SETUP.md](traffic-generator/SETUP.md)

---

### `sanitize/` — Document Sanitizer

Replaces sensitive identifiers in documents before sharing. IPs and MACs are
replaced automatically; names and company names are replaced when specified.

- Supports `.txt`, `.md`, `.csv`, `.log`, `.docx`, `.pdf`
- Substitutions logged to a companion file for auditability
- Preserves MITRE ATT&CK technique IDs and APT names

**Platform:** Windows  
**Setup:** [sanitize/SANITIZE.md](sanitize/SANITIZE.md)
