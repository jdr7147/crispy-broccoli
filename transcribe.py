#!/usr/bin/env python3
"""
Meeting transcription tool.
Records microphone + system audio, transcribes with local Whisper in
real time (chunk by chunk), and optionally separates speakers
(Person A, Person B, …) via pyannote at the end.
"""

import argparse
import contextlib
import io
import logging
import queue
import sys
import tempfile
import threading
import warnings
import wave
from datetime import datetime
from pathlib import Path

import numpy as np
import sounddevice as sd


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def quiet():
    """Suppress noisy library warnings, logging, and stderr chatter."""
    noisy = [
        "pyannote", "pytorch_lightning", "lightning_fabric", "lightning",
        "transformers", "speechbrain", "asteroid_filterbanks", "numba",
        "torch", "whisper",
    ]
    old_levels = {}
    for name in noisy:
        logger = logging.getLogger(name)
        old_levels[name] = logger.level
        logger.setLevel(logging.ERROR)

    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    except Exception:
        captured = sys.stderr.getvalue()
        sys.stderr = old_stderr
        if captured.strip():
            print(captured, file=sys.stderr)
        raise
    finally:
        if sys.stderr is not old_stderr:
            sys.stderr = old_stderr
        for name, level in old_levels.items():
            logging.getLogger(name).setLevel(level)


@contextlib.contextmanager
def progress_spinner(message: str):
    """Show a spinning progress indicator until the block completes."""
    stop = threading.Event()

    def spin():
        chars = "|/-\\"
        i = 0
        while not stop.is_set():
            print(f"\r  {chars[i % 4]} {message} …", end="", flush=True)
            i += 1
            stop.wait(timeout=0.15)
        print(f"\r  {message} … done.          ")

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()


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

def _normalize(audio: np.ndarray) -> np.ndarray:
    peak = np.abs(audio).max()
    return audio / peak if peak > 1e-6 else audio


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


def record_chunked(mic_idx, mon_idx, samplerate, chunk_duration, chunk_queue, stop_event):
    """Record from mic (and optionally monitor) and emit mixed mono chunks."""
    mic_buf = []
    mon_buf = []
    lock = threading.Lock()

    def mic_cb(indata, frames, time, status):
        if status:
            print(f"  [mic] {status}", file=sys.stderr)
        with lock:
            mic_buf.append(indata.copy())

    def mon_cb(indata, frames, time, status):
        if status:
            print(f"  [mon] {status}", file=sys.stderr)
        with lock:
            mon_buf.append(indata.copy())

    def extract():
        with lock:
            mic = np.concatenate(mic_buf, axis=0) if mic_buf else np.zeros((0, 1), dtype="float32")
            mic_buf.clear()
            mon = np.concatenate(mon_buf, axis=0) if mon_buf else None
            mon_buf.clear()
        if mon is not None and len(mon) > 0:
            return mix_to_mono(mic, mon)
        return mic.mean(axis=1) if mic.ndim > 1 else mic.flatten()

    streams = [
        sd.InputStream(device=mic_idx, channels=1, samplerate=samplerate,
                       dtype="float32", callback=mic_cb)
    ]
    if mon_idx is not None:
        streams.append(
            sd.InputStream(device=mon_idx, channels=2, samplerate=samplerate,
                           dtype="float32", callback=mon_cb)
        )

    with contextlib.ExitStack() as stack:
        for s in streams:
            stack.enter_context(s)
        while not stop_event.wait(timeout=chunk_duration):
            chunk_queue.put(extract())
        chunk_queue.put(extract())  # final partial chunk after stop

    chunk_queue.put(None)  # sentinel


# ---------------------------------------------------------------------------
# Transcription (Whisper)
# ---------------------------------------------------------------------------

def load_prompt_config(script_path: Path) -> str:
    """Load initial prompt words from transcribe_config.txt next to the script."""
    config_path = script_path.parent / "transcribe_config.txt"
    if not config_path.exists():
        return ""
    words = []
    for line in config_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.extend(w.strip() for w in line.split(",") if w.strip())
    return ", ".join(words)


def load_whisper_model(model_size: str):
    try:
        import whisper
    except ImportError:
        sys.exit("openai-whisper is not installed. Run: pip install openai-whisper")
    with progress_spinner(f"Loading Whisper model '{model_size}'"), quiet():
        return whisper.load_model(model_size)


def transcribe_chunk(model, audio: np.ndarray, samplerate: int, language: str | None,
                     initial_prompt: str | None, time_offset: float):
    """Transcribe a single audio chunk. Returns (text, segments) with absolute timestamps."""
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tf:
        tmp_path = Path(tf.name)
    try:
        save_wav(tmp_path, audio, samplerate)
        opts = {"word_timestamps": False}
        if language:
            opts["language"] = language
        if initial_prompt:
            opts["initial_prompt"] = initial_prompt
        with quiet():
            result = model.transcribe(str(tmp_path), **opts)
    finally:
        tmp_path.unlink(missing_ok=True)

    text = result["text"].strip()
    segments = [
        {"start": s["start"] + time_offset, "end": s["end"] + time_offset, "text": s["text"]}
        for s in result.get("segments", [])
    ]
    return text, segments


HALLUCINATIONS = {
    "thanks for watching",
    "thank you for watching",
    "thank you for watching!",
    "please subscribe",
    "subscribe to my channel",
    "like and subscribe",
    "see you next time",
    "see you in the next video",
    "don't forget to subscribe",
    "check out my other videos",
}

SILENCE_RMS_THRESHOLD = 0.01


def is_silent(audio: np.ndarray) -> bool:
    return float(np.sqrt(np.mean(audio ** 2))) < SILENCE_RMS_THRESHOLD


def is_hallucination(text: str) -> bool:
    return text.lower().strip().rstrip("!.,") in HALLUCINATIONS


def transcription_worker(chunk_queue, model, language, initial_prompt, samplerate,
                         transcript_path, all_audio, all_segments):
    """Consume audio chunks, transcribe each, and append to transcript file in real time."""
    time_offset = 0.0
    chunk_num = 0

    while True:
        chunk = chunk_queue.get()
        if chunk is None:
            break

        all_audio.append(chunk)
        duration = len(chunk) / samplerate
        chunk_num += 1

        if duration < 1.0:
            time_offset += duration
            continue

        if is_silent(chunk):
            print(f"  [chunk {chunk_num} ({duration:.0f}s): below audio threshold, skipping]", flush=True)
            time_offset += duration
            continue

        print(f"  [chunk {chunk_num} ({duration:.0f}s): transcribing …]", flush=True)
        text, segs = transcribe_chunk(model, chunk, samplerate, language, initial_prompt, time_offset)

        if text and not is_hallucination(text):
            with open(transcript_path, "a", encoding="utf-8") as f:
                f.write(text + "\n")
            print(f"  → {text}")
        else:
            print(f"  [chunk {chunk_num}: no speech detected]")

        all_segments.extend(segs)
        time_offset += duration


# ---------------------------------------------------------------------------
# Speaker diarization (pyannote)
# ---------------------------------------------------------------------------

def diarize(wav_path: Path, hf_token: str, num_speakers: int | None):
    """Return list of (start_sec, end_sec, speaker_id) tuples."""
    try:
        import torch
        from pyannote.audio import Pipeline
    except ImportError:
        sys.exit("pyannote.audio is not installed. Run: pip install pyannote.audio")

    with progress_spinner("Loading speaker diarization model"), quiet():
        pipeline = Pipeline.from_pretrained(
            "pyannote/speaker-diarization-3.1",
            token=hf_token,
        )

    # Load via scipy to bypass torchcodec/FFmpeg on Windows
    import scipy.io.wavfile as wavfile
    sr, data = wavfile.read(str(wav_path))
    if data.dtype == np.int16:
        data = data.astype(np.float32) / 32767.0
    waveform = torch.from_numpy(data).unsqueeze(0)  # (1, samples)
    audio_input = {"waveform": waveform, "sample_rate": sr}

    params = {}
    if num_speakers:
        params["num_speakers"] = num_speakers
    with progress_spinner("Analyzing speakers"), quiet():
        diarization = pipeline(audio_input, **params)

    # DiarizeOutput wraps the Annotation — unwrap it if needed
    annotation = diarization
    for attr in ("diarization", "annotation", "speaker_diarization"):
        if hasattr(diarization, attr):
            candidate = getattr(diarization, attr)
            if hasattr(candidate, "itertracks"):
                annotation = candidate
                break

    if hasattr(annotation, "itertracks"):
        return [
            (turn.start, turn.end, speaker)
            for turn, _, speaker in annotation.itertracks(yield_label=True)
        ]

    raise RuntimeError(
        f"Cannot extract speaker turns from pyannote output (type: {type(diarization)}, "
        f"attrs: {[a for a in dir(diarization) if not a.startswith('_')]}). "
        "Please open an issue with this message."
    )


def assign_speakers(segments, turns):
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
        description="Record a meeting and transcribe it in real time."
    )
    parser.add_argument(
        "--model",
        default="medium",
        choices=["tiny", "base", "small", "medium", "large"],
        help="Whisper model size (default: medium)",
    )
    parser.add_argument("--language", default="en", help="Language code (default: en).")
    parser.add_argument(
        "--initial-prompt",
        default=None,
        help="Words/names to hint Whisper toward. Merged with transcribe_config.txt if present.",
    )
    parser.add_argument(
        "--chunk-duration",
        type=int,
        default=15,
        help="Seconds of audio per transcription chunk (default: 15).",
    )
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

    # Resolve initial prompt: config file first, CLI arg merges in
    config_prompt = load_prompt_config(Path(__file__))
    if args.initial_prompt and config_prompt:
        initial_prompt = f"{config_prompt}, {args.initial_prompt}"
    else:
        initial_prompt = args.initial_prompt or config_prompt or None

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
    print(f"  Language      : {args.language}")
    print(f"  Chunk duration: {args.chunk_duration}s  (first transcript line appears after this many seconds)")
    print(f"  Prompt hints  : {initial_prompt or '(none)'}")
    print(f"  Diarization   : {'yes' if args.diarize else 'no'}")
    print()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    wav_path = args.output_dir / f"meeting_{timestamp}.wav"
    transcript_path = args.output_dir / f"meeting_{timestamp}.txt"

    # Load model before recording starts so there's no delay mid-session
    model = load_whisper_model(args.model)

    print()
    print("Press ENTER to start recording, then press ENTER again to stop.")
    input("  > ready? press ENTER to begin … ")

    # Clear / create transcript file
    transcript_path.write_text("", encoding="utf-8")

    stop_event = threading.Event()
    chunk_q: queue.Queue = queue.Queue()
    all_audio: list[np.ndarray] = []
    all_segments: list[dict] = []

    recorder = threading.Thread(
        target=record_chunked,
        args=(mic_idx, mon_idx, args.samplerate, args.chunk_duration, chunk_q, stop_event),
        daemon=True,
    )
    transcriber = threading.Thread(
        target=transcription_worker,
        args=(chunk_q, model, args.language, initial_prompt,
              args.samplerate, transcript_path, all_audio, all_segments),
        daemon=True,
    )

    recorder.start()
    transcriber.start()

    print("Recording … (press ENTER to stop)")
    input()
    stop_event.set()

    print("Stopping recording …")
    recorder.join()
    print("Finishing transcription …")
    transcriber.join()

    if not all_audio:
        sys.exit("No audio was captured.")

    full_audio = np.concatenate(all_audio)
    total_duration = len(full_audio) / args.samplerate
    print(f"Recorded {total_duration:.1f} seconds of audio.")

    # Normalize the full mix for diarization (equal loudness across speakers)
    save_wav(wav_path, _normalize(full_audio), args.samplerate)
    print(f"Audio saved to {wav_path}")

    if args.diarize and all_segments:
        print()
        turns = diarize(wav_path, args.hf_token, args.num_speakers)
        labeled = assign_speakers(all_segments, turns)
        output_text = format_diarized(labeled)
        transcript_path.write_text(output_text, encoding="utf-8")
        print()
        print("=== TRANSCRIPT (with speaker labels) ===")
        print(output_text)
    else:
        output_text = transcript_path.read_text(encoding="utf-8")
        print()
        print("=== TRANSCRIPT ===")
        print(output_text)

    print(f"\nTranscript saved to {transcript_path}")

    if args.no_audio_save:
        wav_path.unlink()
        print("(WAV file deleted per --no-audio-save)")


if __name__ == "__main__":
    main()
