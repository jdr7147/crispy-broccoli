# Meeting Transcription Tool — Windows Setup Guide

Records your microphone and system audio, transcribes the conversation locally
using OpenAI Whisper (nothing is sent to the cloud for transcription), optionally
labels each speaker as **Person A**, **Person B**, etc., and produces a formatted
set of key notes via the Claude API.

---

## What You Need

| Requirement | Notes |
|---|---|
| Windows 10 or 11 | 64-bit |
| Python 3.10 – 3.12 | 3.13 is **not** recommended (library compatibility) |
| An Anthropic API key | For key-notes generation. Free to create at console.anthropic.com |
| A Hugging Face account + token | Only needed if you want speaker labels (Person A, B, …) |
| ~3 GB free disk space | For Python packages and Whisper models |

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
pip install sounddevice numpy openai-whisper anthropic
```

This installs the audio capture, transcription, and Claude API libraries.
It may take a few minutes — Whisper downloads its own dependencies.

---

## Step 4 — Get an Anthropic API Key

The tool uses the Claude API to generate key notes from your transcript.

1. Go to **console.anthropic.com** and sign in (or create a free account).
2. Click **API Keys** in the left menu.
3. Click **Create Key**, give it a name (e.g. "transcription tool"), and click Create.
4. **Copy the key immediately** — it starts with `sk-ant-` and is only shown once.
5. Keep it somewhere safe (a password manager or a notepad file you store privately).

---

## Step 5 — (Optional) Set Up Speaker Labels

Skip this section if you do not need to know who said what — the tool works fine
without it. Come back here if you want **Person A / Person B** labels.

### 5a — Create a Hugging Face account and token

1. Go to **huggingface.co** and create a free account.
2. Click your profile picture → **Settings** → **Access Tokens**.
3. Click **New token**, name it anything, set role to **Read**, and create it.
4. Copy the token (starts with `hf_`).

### 5b — Accept the model license agreements

The speaker-labeling models are gated and require you to accept terms on three
separate pages. Sign in to Hugging Face, then visit each link below and click
**"Agree and access repository"**:

- huggingface.co/pyannote/speaker-diarization-3.1
- huggingface.co/pyannote/segmentation-3.0
- huggingface.co/pyannote/speaker-diarization-community-1

### 5c — Install the diarization library

```
pip install pyannote.audio
```

> **Note:** This also installs PyTorch (~2 GB). The download may take several minutes.

---

## Step 6 — Download the Script

Save `transcribe.py` to a folder you can find easily, for example:

```
C:\Users\YourName\Downloads\transcribe.py
```

---

## Step 7 — Run the Tool

Open Command Prompt, activate the virtual environment, then navigate to where
you saved the script:

```
C:\venv\Scripts\activate
cd C:\Users\YourName\Downloads
```

### Basic usage (transcript only, no speaker labels)

```
python transcribe.py --anthropic-key "sk-ant-YOUR_KEY_HERE"
```

### With speaker labels

```
python transcribe.py --anthropic-key "sk-ant-YOUR_KEY_HERE" --diarize --hf-token "hf_YOUR_TOKEN_HERE"
```

Press **Enter** to start recording, speak, then press **Enter** again to stop.
The tool will transcribe the audio, generate key notes, and open the notes file
automatically.

---

## All Available Arguments

| Argument | Default | Description |
|---|---|---|
| `--anthropic-key KEY` | *(required unless `--no-notes`)* | Your Anthropic API key for key-notes generation. Alternatively, set the `ANTHROPIC_API_KEY` environment variable and omit this flag. |
| `--model SIZE` | `base` | Whisper model size. Larger = more accurate but slower. Choices: `tiny`, `base`, `small`, `medium`, `large`. Start with `base`; upgrade to `small` or `medium` if accuracy is poor. |
| `--language CODE` | *(auto-detect)* | Force a language, e.g. `--language en`. Speeds up transcription and improves accuracy when you know the language. |
| `--samplerate HZ` | `16000` | Audio sample rate in Hz. 16000 is correct for Whisper and rarely needs changing. |
| `--output-dir PATH` | `.` (current folder) | Folder where transcript and notes files are saved. Created automatically if it does not exist. Example: `--output-dir C:\Meetings` |
| `--list-devices` | — | Print all audio devices and their index numbers, then exit. Use this to find the right `--mic-device` or `--monitor-device` index if the tool picks the wrong device. |
| `--mic-device INDEX` | *(auto-detect)* | Device index for your microphone. Get the index from `--list-devices`. |
| `--monitor-device INDEX` | *(auto-detect)* | Device index for system audio (what plays through your speakers). The tool looks for WASAPI loopback / "Stereo Mix" automatically. Use this flag if it picks the wrong one. |
| `--no-audio-save` | — | Delete the recorded `.wav` file after transcription. By default the audio is kept alongside the transcript. |
| `--diarize` | — | Enable speaker labeling (Person A, Person B, …). Requires `--hf-token` and the optional pyannote install from Step 5. |
| `--hf-token TOKEN` | *(required with `--diarize`)* | Your Hugging Face access token. See Step 5. |
| `--num-speakers N` | *(auto-detect)* | Tell the diarization model exactly how many speakers were in the meeting. Providing this improves accuracy when you know the number. Example: `--num-speakers 3` |
| `--no-notes` | — | Skip the Claude API call entirely. The transcript is still saved and printed, but no key-notes file is generated. Useful if you do not have an API key or want to save API costs. |

---

## Output Files

All files are saved in the output directory (default: same folder as the script)
with a timestamp in the name.

| File | Contents |
|---|---|
| `meeting_YYYYMMDD_HHMMSS.wav` | Raw audio recording |
| `meeting_YYYYMMDD_HHMMSS.txt` | Full transcript (with speaker labels if `--diarize` was used) |
| `meeting_YYYYMMDD_HHMMSS_notes.txt` | Key notes generated by Claude (omitted with `--no-notes`) |

The notes file opens automatically when transcription is complete.

---

## Saving Your API Key Permanently

Instead of typing `--anthropic-key` every time, save the key as a Windows
environment variable:

1. Press `Win + S`, search for **"Edit the system environment variables"**, and open it.
2. Click **Environment Variables…**
3. Under **User variables**, click **New**.
4. Variable name: `ANTHROPIC_API_KEY`
5. Variable value: your key (`sk-ant-...`)
6. Click OK on all windows.
7. Open a **new** Command Prompt window for the change to take effect.

After this, you can run the tool without `--anthropic-key`:

```
python transcribe.py
```

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
setting `--language en` (or your language code) to skip auto-detection.

**Speaker labels are all "Person A"**
Diarization works best with clear audio and at least a few seconds of each
speaker talking. Try `--num-speakers 2` (or however many speakers there were)
to give the model a hint.

**"invalid x-api-key" from Anthropic**
Your API key is wrong or expired. Return to Step 4, create a new key, and copy
it carefully — no extra spaces or quote characters.

**pip install fails with long path error**
Make sure you created the virtual environment at `C:\venv` as shown in Step 2,
not inside a deep user profile folder.
