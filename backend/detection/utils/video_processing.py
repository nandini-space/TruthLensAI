"""Local PyAV video validation and bounded media extraction helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import VideoDetectionConfig


@dataclass(frozen=True, slots=True)
class VideoData:
    path: Path
    video_format: str
    duration_seconds: float | None
    width: int | None
    height: int | None
    fps: float | None
    frame_count: int | None
    audio_present: bool


class PyAvVideoProcessor:
    """Uses local PyAV codecs; no media is uploaded or retained."""

    def inspect(self, path_value: str, config: VideoDetectionConfig) -> tuple[VideoData | None, str | None]:
        path = Path(path_value)
        if not path.is_file():
            return None, "video_file_not_found"
        if path.stat().st_size > config.max_file_bytes:
            return None, "video_file_too_large"
        video_format = path.suffix.removeprefix(".").upper()
        if video_format not in config.allowed_formats:
            return None, "unsupported_video_format"
        try:
            import av

            with av.open(str(path)) as container:
                stream = next((item for item in container.streams if item.type == "video"), None)
                if stream is None:
                    return None, "video_stream_not_found"
                duration = float(container.duration / av.time_base) if container.duration is not None else None
                fps = float(stream.average_rate) if stream.average_rate else None
                return VideoData(
                    path=path,
                    video_format=video_format,
                    duration_seconds=round(duration, 3) if duration is not None else None,
                    width=stream.codec_context.width or None,
                    height=stream.codec_context.height or None,
                    fps=round(fps, 3) if fps is not None else None,
                    frame_count=stream.frames or None,
                    audio_present=any(item.type == "audio" for item in container.streams),
                ), None
        except ImportError:
            return None, "video_processing_unavailable"
        except Exception:
            return None, "invalid_or_corrupt_video"

    def extract_frames(self, video: VideoData, output_directory: Path, count: int) -> list[Path]:
        if count < 1:
            return []
        import av

        output_directory.mkdir(parents=True, exist_ok=True)
        fractions = [0.0] if count == 1 else [index / (count - 1) for index in range(count)]
        # Avoid seeking to the exact final timestamp, which can be beyond the last decodable frame.
        timestamps = [fraction * (video.duration_seconds or 0) * (0.999 if fraction == 1 else 1) for fraction in fractions]
        frames: list[Path] = []
        with av.open(str(video.path)) as container:
            stream = next(item for item in container.streams if item.type == "video")
            for index, timestamp in enumerate(timestamps):
                if stream.time_base is not None:
                    container.seek(max(0, int(timestamp / float(stream.time_base))), stream=stream, any_frame=False, backward=True)
                frame = next(container.decode(stream), None)
                if frame is None:
                    continue
                target = output_directory / f"frame_{index + 1}.png"
                frame.to_image().save(target, format="PNG")
                frames.append(target)
        return frames

    def extract_audio(self, video: VideoData, output_path: Path) -> Path | None:
        if not video.audio_present:
            return None
        import av

        with av.open(str(video.path)) as source:
            input_stream = next((item for item in source.streams if item.type == "audio"), None)
            if input_stream is None:
                return None
            sample_rate = input_stream.codec_context.sample_rate or 16_000
            with av.open(str(output_path), "w", format="wav") as destination:
                output_stream = destination.add_stream("pcm_s16le", rate=sample_rate)
                for frame in source.decode(input_stream):
                    for packet in output_stream.encode(frame):
                        destination.mux(packet)
                for packet in output_stream.encode(None):
                    destination.mux(packet)
        return output_path
