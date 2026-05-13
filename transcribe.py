#!/usr/bin/env python3
"""
Meeting transcription tool.
Records microphone + system audio, then transcribes with local Whisper.
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


def find_system_monitor(devices):
    """Return the first PulseAudio/PipeWire monitor source index, or None."""
    for i, dev in enumerate(devices):
        name = dev["name"].lower()
        if "monitor" in name and dev["max_input_channels"] > 0:
            return i
    return None


def find_default_mic(devices):
    """Return the default input device index."""
    for i, dev in enumerate(devices):
        if dev["max_input_channels"] > 0 and "monitor" not in dev["name"].lower():
            # prefer the default
            try:
                default = sd.default.device[0]
                if i == default:
                    return i
            except Exception:
                pass
    # fallback: first non-monitor input
    for i, dev in enumerate(devices):
        if dev["max_input_channels"] > 0 and "monitor" not in dev["name"].lower():
            return i
    return None


def record_stream(device_index, samplerate, channels, out_queue, stop_event):
    """Record from a single device into out_queue until stop_event is set."""
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

    out_queue.put(np.concatenate(buf, axis=0) if buf else np.zeros((0, channels), dtype="float32"))


def mix_to_mono(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Mix two float32 arrays (possibly different channel counts) to mono, matching length."""
    a_mono = a.mean(axis=1) if a.ndim > 1 else a.flatten()
    b_mono = b.mean(axis=1) if b.ndim > 1 else b.flatten()
    min_len = min(len(a_mono), len(b_mono))
    mixed = (a_mono[:min_len] + b_mono[:min_len]) / 2.0
    return np.clip(mixed, -1.0, 1.0)


def save_wav(path: Path, audio: np.ndarray, samplerate: int):
    pcm = (audio * 32767).astype(np.int16)
    with wave.open(str(path), "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(samplerate)
        wf.writeframes(pcm.tobytes())


def transcribe(wav_path: Path, model_size: str, language: str | None) -> str:
    try:
        import whisper
    except ImportError:
        sys.exit("openai-whisper is not installed. Run: pip install openai-whisper")

    print(f"Loading Whisper model '{model_size}' …")
    model = whisper.load_model(model_size)
    print("Transcribing …")
    options = {}
    if language:
        options["language"] = language
    result = model.transcribe(str(wav_path), **options)
    return result["text"].strip()


def main():
    parser = argparse.ArgumentParser(
        description="Record a meeting (mic + system audio) and transcribe it with Whisper."
    )
    parser.add_argument(
        "--model",
        default="base",
        choices=["tiny", "base", "small", "medium", "large"],
        help="Whisper model size (default: base)",
    )
    parser.add_argument(
        "--language",
        default=None,
        help="Language code (e.g. 'en'). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--samplerate",
        type=int,
        default=16000,
        help="Sample rate in Hz (default: 16000)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="Directory for saved recordings and transcripts (default: current dir)",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="Print available audio devices and exit.",
    )
    parser.add_argument(
        "--mic-device",
        type=int,
        default=None,
        help="Override microphone device index (see --list-devices).",
    )
    parser.add_argument(
        "--monitor-device",
        type=int,
        default=None,
        help="Override system-audio monitor device index (see --list-devices).",
    )
    parser.add_argument(
        "--no-audio-save",
        action="store_true",
        help="Delete the WAV file after transcription.",
    )
    args = parser.parse_args()

    devices = sd.query_devices()

    if args.list_devices:
        print(f"{'IDX':>4}  {'NAME':<55} IN  OUT")
        for i, d in enumerate(devices):
            print(f"{i:>4}  {d['name']:<55} {d['max_input_channels']:>2}  {d['max_output_channels']:>3}")
        return

    mic_idx = args.mic_device if args.mic_device is not None else find_default_mic(devices)
    mon_idx = args.monitor_device if args.monitor_device is not None else find_system_monitor(devices)

    if mic_idx is None:
        sys.exit("No microphone found. Use --list-devices to inspect inputs.")

    print("=== Meeting Transcription Tool ===")
    print(f"  Microphone    : [{mic_idx}] {devices[mic_idx]['name']}")
    if mon_idx is not None:
        print(f"  System audio  : [{mon_idx}] {devices[mon_idx]['name']}")
    else:
        print("  System audio  : not found — recording microphone only")
    print(f"  Whisper model : {args.model}")
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

    text = transcribe(wav_path, args.model, args.language)

    transcript_path.write_text(text, encoding="utf-8")
    print(f"Transcript saved to {transcript_path}")
    print()
    print("=== TRANSCRIPT ===")
    print(text)

    if args.no_audio_save:
        wav_path.unlink()
        print(f"(WAV file deleted per --no-audio-save)")


if __name__ == "__main__":
    main()
