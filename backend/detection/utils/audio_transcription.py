"""Local audio validation and optional faster-whisper transcription boundary."""

from __future__ import annotations

import wave
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..config import AudioDetectionConfig


@dataclass(frozen=True, slots=True)
class AudioData:
    path: Path
    audio_format: str
    duration_seconds: float | None
    sample_rate: int | None
    channels: int | None
    preprocessing: str


@dataclass(frozen=True, slots=True)
class TranscriptionResult:
    status: str
    text: str = ""
    confidence: float | None = None
    error: str | None = None


class SpeechToTextEngine(Protocol):
    def transcribe(self, audio: AudioData) -> TranscriptionResult:
        """Transcribe a validated local audio file without remote services."""


def load_audio_metadata(path_value: str, config: AudioDetectionConfig) -> tuple[AudioData | None, str | None]:
    """Validate a local audio file and collect non-destructive metadata where available."""
    path = Path(path_value)
    if not path.is_file():
        return None, "audio_file_not_found"
    if path.stat().st_size > config.max_file_bytes:
        return None, "audio_file_too_large"

    audio_format = path.suffix.removeprefix(".").upper()
    if audio_format not in config.allowed_formats:
        return None, "unsupported_audio_format"
    try:
        if audio_format == "WAV":
            with wave.open(str(path), "rb") as opened:
                sample_rate = opened.getframerate()
                channels = opened.getnchannels()
                duration_seconds = opened.getnframes() / sample_rate if sample_rate else None
        else:
            # Mutagen validates MP3/M4A/FLAC headers without decoding full audio.
            from mutagen import File as MutagenFile

            parsed = MutagenFile(path)
            if parsed is None or parsed.info is None:
                return None, "invalid_or_corrupt_audio"
            info = parsed.info
            duration_seconds = getattr(info, "length", None)
            sample_rate = getattr(info, "sample_rate", None)
            channels = getattr(info, "channels", None)
        return AudioData(
            path=path,
            audio_format=audio_format,
            duration_seconds=round(duration_seconds, 3) if duration_seconds is not None else None,
            sample_rate=sample_rate,
            channels=channels,
            preprocessing="not_applied",
        ), None
    except (OSError, EOFError, ImportError, wave.Error):
        return None, "invalid_or_corrupt_audio"


class FasterWhisperTranscriber:
    """Optional adapter for a pre-downloaded local faster-whisper model."""

    def __init__(self, config: AudioDetectionConfig | None = None) -> None:
        self._config = config or AudioDetectionConfig()

    def transcribe(self, audio: AudioData) -> TranscriptionResult:
        if not self._config.transcription_model_path:
            return TranscriptionResult(
                status="unavailable",
                error="local_transcription_model_not_configured",
            )
        try:
            from faster_whisper import WhisperModel

            model = WhisperModel(
                self._config.transcription_model_path,
                device=self._config.transcription_device,
                compute_type=self._config.transcription_compute_type,
            )
            segments, _ = model.transcribe(str(audio.path))
            text = " ".join(segment.text.strip() for segment in segments if segment.text.strip())
            return TranscriptionResult(status="success", text=text) if text else TranscriptionResult(status="no_speech")
        except ImportError:
            return TranscriptionResult(status="unavailable", error="faster_whisper_not_installed")
        except Exception as error:
            return TranscriptionResult(status="failed", error=type(error).__name__)
