# Meeting Transcription Tool — Windows Setup Guide

Records your microphone and system audio, transcribes the conversation locally
using OpenAI Whisper (nothing leaves your machine), and optionally labels each
speaker as **Person A**, **Person B**, etc.

---

## What You Need

| Requirement | Notes |
|---|---|
| Windows 10 or 11 | 64-bit |
| Python 3.10 – 3.12 | 3.13 is **not** recommended (library compatibility) |
| ~3 GB free disk space | For Python packages and Whisper models |
| A Hugging Face account + token | Only needed if you want speaker labels (Person A, B, …) |

---

## Step 1 — Install Python

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

## Step 2 — Create a Virtual Environment

Windows has a file-path length limit that breaks package installation if your
username is long. To avoid this, create the virtual environment at the root of
your `C:\` drive.

In Command Prompt, run **exactly**:

```
python -m venv C:\venv
```

Then activate it:

```
C:\venv\Scripts\activate
```

Your prompt should now start with `(venv)`. You must activate this environment
**every time** you open a new Command Prompt window before running the tool.

---

## Step 3 — Install Required Packages

With the environment activated, run:

```
pip install sounddevice numpy openai-whisper
```

This may take a few minutes — Whisper downloads its own dependencies.

---

## Step 4 — Download the Files

Save both files to the same folder, for example `C:\Users\YourName\Downloads\`:

- `transcribe.py` — the main tool
- `transcribe_config.txt` — your personal word hints (names, terms)

---

## Step 5 — Add Your Names to the Config File

Open `transcribe_config.txt` in Notepad. It looks like this:

```
# People
Jarrett, Ash, Nic

# Add company names, product names, acronyms, or technical terms below:
```

Edit the names and add any words that Whisper tends to mishear — company names,
product names, acronyms, technical terms. Save the file. The tool reads it
automatically every time it runs, so Whisper will recognise those words correctly.

Lines starting with `#` are comments and are ignored.

---

## Step 6 — Run the Tool

Open Command Prompt, activate the virtual environment, then navigate to the
folder containing the script:

```
C:\venv\Scripts\activate
cd C:\Users\YourName\Downloads
```

### Basic usage (transcript only, no speaker labels)

```
python transcribe.py
```

### With speaker labels

```
python transcribe.py --diarize --hf-token "hf_YOUR_TOKEN_HERE"
```

Press **Enter** to start recording, speak, then press **Enter** again to stop.
The transcript is saved to a `.txt` file and printed to the screen.

---

## Step 7 — (Optional) Set Up Speaker Labels

Skip this section if you do not need to know who said what.

### 7a — Create a Hugging Face account and token

1. Go to **huggingface.co** and create a free account.
2. Click your profile picture → **Settings** → **Access Tokens**.
3. Click **New token**, name it anything, set role to **Read**, and create it.
4. Copy the token (starts with `hf_`).

### 7b — Accept the model license agreements

The speaker-labeling models are gated and require you to accept terms on three
separate pages. Sign in to Hugging Face, then visit each link below and click
**"Agree and access repository"**:

- huggingface.co/pyannote/speaker-diarization-3.1
- huggingface.co/pyannote/segmentation-3.0
- huggingface.co/pyannote/speaker-diarization-community-1

### 7c — Install the diarization library

```
pip install pyannote.audio
```

> **Note:** This also installs PyTorch (~2 GB). The download may take several minutes.

---

## All Available Arguments

| Argument | Default | Description |
|---|---|---|
| `--model SIZE` | `base` | Whisper model size. Larger = more accurate but slower. Choices: `tiny`, `base`, `small`, `medium`, `large`. Start with `base`; upgrade to `small` or `medium` if accuracy is poor. |
| `--language CODE` | *(auto-detect)* | Force a language, e.g. `--language en`. Speeds up transcription and improves accuracy when you know the language. |
| `--initial-prompt "WORDS"` | *(from config file)* | Names or terms to hint Whisper toward for this session only. Merged with `transcribe_config.txt` automatically. Example: `--initial-prompt "Salesforce, Q3 roadmap"` |
| `--samplerate HZ` | `16000` | Audio sample rate in Hz. 16000 is correct for Whisper and rarely needs changing. |
| `--output-dir PATH` | `.` (current folder) | Folder where transcript and audio files are saved. Created automatically if it does not exist. Example: `--output-dir C:\Meetings` |
| `--list-devices` | — | Print all audio devices and their index numbers, then exit. Use this to find the right `--mic-device` or `--monitor-device` index if the tool picks the wrong device. |
| `--mic-device INDEX` | *(auto-detect)* | Device index for your microphone. Get the index from `--list-devices`. |
| `--monitor-device INDEX` | *(auto-detect)* | Device index for system audio (what plays through your speakers). The tool looks for WASAPI loopback / "Stereo Mix" automatically. Use this flag if it picks the wrong one. |
| `--no-audio-save` | — | Delete the recorded `.wav` file after transcription. By default the audio is kept alongside the transcript. |
| `--diarize` | — | Enable speaker labeling (Person A, Person B, …). Requires `--hf-token` and the optional pyannote install from Step 7. |
| `--hf-token TOKEN` | *(required with `--diarize`)* | Your Hugging Face access token. See Step 7. |
| `--num-speakers N` | *(auto-detect)* | Tell the diarization model exactly how many speakers were in the meeting. Providing this improves accuracy when you know the number. Example: `--num-speakers 3` |

---

## Output Files

All files are saved in the output directory (default: same folder as the script)
with a timestamp in the name.

| File | Contents |
|---|---|
| `meeting_YYYYMMDD_HHMMSS.wav` | Raw audio recording |
| `meeting_YYYYMMDD_HHMMSS.txt` | Full transcript (with speaker labels if `--diarize` was used) |

---

## Troubleshooting

**"No microphone found"**
Run `python transcribe.py --list-devices` to see all devices, then pass the
correct index with `--mic-device INDEX`.

**System audio (meeting audio) is not being captured**
Your sound card may not expose a loopback device by default. Open Windows Sound
settings → Recording tab → right-click in the device list → "Show Disabled
Devices" → enable **Stereo Mix** if it appears. Then re-run the tool.

**Transcription is inaccurate**
Try a larger Whisper model: `--model small` or `--model medium`. Also try
setting `--language en` (or your language code) to skip auto-detection. Make
sure names and terms are listed in `transcribe_config.txt`.

**Speaker labels are all "Person A"**
Diarization works best with clear audio and at least a few seconds of each
speaker talking. Try `--num-speakers 2` (or however many speakers there were)
to give the model a hint.

**pip install fails with long path error**
Make sure you created the virtual environment at `C:\venv` as shown in Step 2,
not inside a deep user profile folder.

**"No module named 'sounddevice'" or similar**
The virtual environment is not active. Run `C:\venv\Scripts\activate` first,
then try again.
