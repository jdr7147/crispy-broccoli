#!/usr/bin/env python3
"""
Meeting transcription tool.
Records microphone + system audio, transcribes with local Whisper,
and optionally separates speakers (Person A, Person B, …) via pyannote.
"""

import argparse
import queue
import sys
import threading
import wave
from datetime import datetime
from pathlib import Path

import numpy as np
import sounddevice as sd


# ---------------------------------------------------------------------------
# Audio device helpers
# ---------------------------------------------------------------------------

def find_loopback_device(devices):
    """Return a WASAPI loopback / PulseAudio monitor device index, or None."""
    keywords = ("loopback", "monitor", "stereo mix", "what u hear", "wave out mix")
    for i, dev in enumerate(devices):
        name = dev["name"].lower()
        if dev["max_input_channels"] > 0 and any(k in name for k in keywords):
            return i
    return None


def find_default_mic(devices):
    """Return the default microphone device index."""
    try:
        default = sd.default.device[0]
        if default is not None and default >= 0:
            dev = devices[default]
            if dev["max_input_channels"] > 0 and "loopback" not in dev["name"].lower():
                return default
    except Exception:
        pass
    for i, dev in enumerate(devices):
        name = dev["name"].lower()
        if dev["max_input_channels"] > 0 and not any(
            k in name for k in ("loopback", "monitor", "stereo mix", "what u hear")
        ):
            return i
    return None


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def record_stream(device_index, samplerate, channels, out_queue, stop_event):
    buf = []

    def callback(indata, frames, time, status):
        if status:
            print(f"  [stream warning] {status}", file=sys.stderr)
        buf.append(indata.copy())

    with sd.InputStream(
        device=device_index,
        channels=channels,
        samplerate=samplerate,
        dtype="float32",
        callback=callback,
    ):
        stop_event.wait()

    out_queue.put(
        np.concatenate(buf, axis=0) if buf else np.zeros((0, channels), dtype="float32")
    )


def mix_to_mono(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    a_mono = a.mean(axis=1) if a.ndim > 1 else a.flatten()
    b_mono = b.mean(axis=1) if b.ndim > 1 else b.flatten()
    n = min(len(a_mono), len(b_mono))
    return np.clip((a_mono[:n] + b_mono[:n]) / 2.0, -1.0, 1.0)


def save_wav(path: Path, audio: np.ndarray, samplerate: int):
    pcm = (audio * 32767).astype(np.int16)
    with wave.open(str(path), "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(samplerate)
        wf.writeframes(pcm.tobytes())


# ---------------------------------------------------------------------------
# Transcription (Whisper)
# ---------------------------------------------------------------------------

def transcribe_segments(wav_path: Path, model_size: str, language: str | None):
    """Return (full_text, segments) where segments have start/end/text keys."""
    try:
        import whisper
    except ImportError:
        sys.exit("openai-whisper is not installed. Run: pip install openai-whisper")

    print(f"Loading Whisper model '{model_size}' …")
    model = whisper.load_model(model_size)
    print("Transcribing …")
    opts = {"word_timestamps": False}
    if language:
        opts["language"] = language
    result = model.transcribe(str(wav_path), **opts)
    return result["text"].strip(), result.get("segments", [])


# ---------------------------------------------------------------------------
# Speaker diarization (pyannote)
# ---------------------------------------------------------------------------

def diarize(wav_path: Path, hf_token: str, num_speakers: int | None):
    """Return list of (start_sec, end_sec, speaker_id) tuples."""
    try:
        from pyannote.audio import Pipeline
    except ImportError:
        sys.exit(
            "pyannote.audio is not installed. Run: pip install pyannote.audio"
        )

    print("Loading speaker diarization model …")
    pipeline = Pipeline.from_pretrained(
        "pyannote/speaker-diarization-3.1",
        use_auth_token=hf_token,
    )
    print("Running diarization …")
    params = {}
    if num_speakers:
        params["num_speakers"] = num_speakers
    diarization = pipeline(str(wav_path), **params)
    return [
        (turn.start, turn.end, speaker)
        for turn, _, speaker in diarization.itertracks(yield_label=True)
    ]


def assign_speakers(segments, turns):
    """
    Map each Whisper segment to the speaker with the greatest time overlap.
    Returns list of (label, text) where label is 'Person A', 'Person B', etc.
    """
    speaker_map: dict[str, str] = {}
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    labeled = []

    for seg in segments:
        s, e, text = seg["start"], seg["end"], seg["text"].strip()
        best_spk, best_overlap = None, 0.0
        for t_start, t_end, spk in turns:
            overlap = max(0.0, min(e, t_end) - max(s, t_start))
            if overlap > best_overlap:
                best_overlap, best_spk = overlap, spk
        if best_spk is None:
            label = "Unknown"
        else:
            if best_spk not in speaker_map:
                speaker_map[best_spk] = f"Person {alphabet[len(speaker_map)]}"
            label = speaker_map[best_spk]
        labeled.append((label, text))

    return labeled


def format_diarized(labeled: list[tuple[str, str]]) -> str:
    """Merge consecutive same-speaker segments into one block."""
    lines = []
    current_speaker, current_text = None, []
    for speaker, text in labeled:
        if speaker == current_speaker:
            current_text.append(text)
        else:
            if current_speaker is not None:
                lines.append(f"{current_speaker}: {' '.join(current_text)}")
            current_speaker, current_text = speaker, [text]
    if current_speaker:
        lines.append(f"{current_speaker}: {' '.join(current_text)}")
    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Record a meeting and transcribe it, with optional speaker labels."
    )
    parser.add_argument(
        "--model",
        default="base",
        choices=["tiny", "base", "small", "medium", "large"],
        help="Whisper model size (default: base)",
    )
    parser.add_argument("--language", default=None, help="Language code, e.g. 'en'.")
    parser.add_argument("--samplerate", type=int, default=16000)
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--list-devices", action="store_true")
    parser.add_argument("--mic-device", type=int, default=None)
    parser.add_argument("--monitor-device", type=int, default=None)
    parser.add_argument("--no-audio-save", action="store_true")

    # Speaker diarization
    parser.add_argument(
        "--diarize",
        action="store_true",
        help="Separate speakers (Person A, Person B, …). Requires --hf-token.",
    )
    parser.add_argument(
        "--hf-token",
        default=None,
        help="Hugging Face access token (needed for diarization).",
    )
    parser.add_argument(
        "--num-speakers",
        type=int,
        default=None,
        help="Hint: exact number of speakers, if known.",
    )

    args = parser.parse_args()

    if args.diarize and not args.hf_token:
        sys.exit(
            "Speaker diarization requires a Hugging Face token.\n"
            "Pass it with --hf-token YOUR_TOKEN\n"
            "Get one free at: https://huggingface.co/settings/tokens\n"
            "(Also accept the model terms at: "
            "https://huggingface.co/pyannote/speaker-diarization-3.1)"
        )

    devices = sd.query_devices()

    if args.list_devices:
        print(f"{'IDX':>4}  {'NAME':<55} IN  OUT")
        for i, d in enumerate(devices):
            print(
                f"{i:>4}  {d['name']:<55} "
                f"{d['max_input_channels']:>2}  {d['max_output_channels']:>3}"
            )
        return

    mic_idx = args.mic_device if args.mic_device is not None else find_default_mic(devices)
    mon_idx = args.monitor_device if args.monitor_device is not None else find_loopback_device(devices)

    if mic_idx is None:
        sys.exit("No microphone found. Use --list-devices to inspect inputs.")

    print("=== Meeting Transcription Tool ===")
    print(f"  Microphone    : [{mic_idx}] {devices[mic_idx]['name']}")
    if mon_idx is not None:
        print(f"  System audio  : [{mon_idx}] {devices[mon_idx]['name']}")
    else:
        print("  System audio  : not found — recording microphone only")
    print(f"  Whisper model : {args.model}")
    print(f"  Diarization   : {'yes' if args.diarize else 'no'}")
    print()
    print("Press ENTER to start recording, then press ENTER again to stop.")
    input("  > ready? press ENTER to begin … ")

    stop_event = threading.Event()
    mic_q: queue.Queue = queue.Queue()
    mon_q: queue.Queue = queue.Queue()

    threads = [
        threading.Thread(
            target=record_stream,
            args=(mic_idx, args.samplerate, 1, mic_q, stop_event),
            daemon=True,
        )
    ]
    if mon_idx is not None:
        threads.append(
            threading.Thread(
                target=record_stream,
                args=(mon_idx, args.samplerate, 2, mon_q, stop_event),
                daemon=True,
            )
        )

    for t in threads:
        t.start()

    print("Recording … (press ENTER to stop)")
    input()
    stop_event.set()

    print("Stopping …")
    for t in threads:
        t.join()

    mic_audio = mic_q.get()
    if mon_idx is not None and not mon_q.empty():
        mon_audio = mon_q.get()
        audio = mix_to_mono(mic_audio, mon_audio)
    else:
        audio = mic_audio.mean(axis=1) if mic_audio.ndim > 1 else mic_audio.flatten()

    duration = len(audio) / args.samplerate
    print(f"Recorded {duration:.1f} seconds of audio.")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    wav_path = args.output_dir / f"meeting_{timestamp}.wav"
    transcript_path = args.output_dir / f"meeting_{timestamp}.txt"

    save_wav(wav_path, audio, args.samplerate)
    print(f"Audio saved to {wav_path}")

    full_text, segments = transcribe_segments(wav_path, args.model, args.language)

    if args.diarize and segments:
        turns = diarize(wav_path, args.hf_token, args.num_speakers)
        labeled = assign_speakers(segments, turns)
        output_text = format_diarized(labeled)
    else:
        output_text = full_text

    transcript_path.write_text(output_text, encoding="utf-8")
    print(f"Transcript saved to {transcript_path}")
    print()
    print("=== TRANSCRIPT ===")
    print(output_text)

    if args.no_audio_save:
        wav_path.unlink()
        print("(WAV file deleted per --no-audio-save)")


if __name__ == "__main__":
    main()
