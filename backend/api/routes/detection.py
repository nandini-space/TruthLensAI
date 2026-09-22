"""Thin, validated HTTP adapters around the existing detection pipeline."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl

from backend.detection.config import AudioDetectionConfig, ImageDetectionConfig, VideoDetectionConfig
from backend.detection.pipeline import DetectionPipeline
from backend.detection.schemas import InputType, ScanRequest, ScanResult

router = APIRouter(tags=["detection"])


class TextScanBody(BaseModel):
    text: str = Field(min_length=1, description="Text to evaluate.")


class UrlScanBody(BaseModel):
    url: HttpUrl = Field(description="Absolute HTTP(S) URL to evaluate.")


class ApiError(BaseModel):
    error: str
    detail: str


def get_pipeline() -> DetectionPipeline:
    """Dependency seam used by API tests and application integrations."""
    return DetectionPipeline()


@router.get("/health", summary="Service health")
def health(request: Request) -> dict[str, str]:
    return {"status": "ok", "service": getattr(request.app.state, "service_name", "TruthLensAI Detection API")}


def _error(code: str, detail: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"error": code, "detail": detail})


@router.post("/scan/text", response_model=ScanResult, responses={500: {"model": ApiError}})
def scan_text(body: TextScanBody, pipeline: Annotated[DetectionPipeline, Depends(get_pipeline)]) -> ScanResult:
    return _scan(pipeline, ScanRequest(input_type=InputType.TEXT, content=body.text))


@router.post("/scan/url", response_model=ScanResult, responses={500: {"model": ApiError}})
def scan_url(body: UrlScanBody, pipeline: Annotated[DetectionPipeline, Depends(get_pipeline)]) -> ScanResult:
    return _scan(pipeline, ScanRequest(input_type=InputType.URL, content=str(body.url)))


@router.post("/scan/image", response_model=ScanResult, responses={400: {"model": ApiError}, 413: {"model": ApiError}, 500: {"model": ApiError}})
def scan_image(file: Annotated[UploadFile, File(description="PNG, JPEG, or WEBP image.")], pipeline: Annotated[DetectionPipeline, Depends(get_pipeline)]) -> ScanResult:
    return _scan_upload(pipeline, file, InputType.IMAGE)


@router.post("/scan/audio", response_model=ScanResult, responses={400: {"model": ApiError}, 413: {"model": ApiError}, 500: {"model": ApiError}})
def scan_audio(file: Annotated[UploadFile, File(description="WAV, MP3, M4A, or FLAC audio.")], pipeline: Annotated[DetectionPipeline, Depends(get_pipeline)]) -> ScanResult:
    return _scan_upload(pipeline, file, InputType.AUDIO)


@router.post("/scan/video", response_model=ScanResult, responses={400: {"model": ApiError}, 413: {"model": ApiError}, 500: {"model": ApiError}})
def scan_video(file: Annotated[UploadFile, File(description="MP4, AVI, MOV, MKV, or WEBM video.")], pipeline: Annotated[DetectionPipeline, Depends(get_pipeline)]) -> ScanResult:
    return _scan_upload(pipeline, file, InputType.VIDEO)


@router.post("/scan/multimodal", response_model=ScanResult, responses={400: {"model": ApiError}, 413: {"model": ApiError}, 500: {"model": ApiError}})
def scan_multimodal(
    pipeline: Annotated[DetectionPipeline, Depends(get_pipeline)],
    text: Annotated[str | None, Form(min_length=1)] = None,
    url: Annotated[HttpUrl | None, Form()] = None,
    image: Annotated[UploadFile | None, File()] = None,
    audio: Annotated[UploadFile | None, File()] = None,
    video: Annotated[UploadFile | None, File()] = None,
) -> ScanResult:
    """Scan supplied modalities with the pipeline, then use its Stage 8 fusion."""
    results: list[ScanResult] = []
    if text is not None:
        results.append(_scan(pipeline, ScanRequest(input_type=InputType.TEXT, content=text)))
    if url is not None:
        results.append(_scan(pipeline, ScanRequest(input_type=InputType.URL, content=str(url))))
    for uploaded, modality in ((image, InputType.IMAGE), (audio, InputType.AUDIO), (video, InputType.VIDEO)):
        if uploaded is not None:
            results.append(_scan_upload(pipeline, uploaded, modality))
    if not results:
        raise _error("missing_modalities", "Provide at least one text, url, image, audio, or video input.", status.HTTP_422_UNPROCESSABLE_ENTITY)
    return _fuse(pipeline, results)


def _scan(pipeline: DetectionPipeline, request: ScanRequest) -> ScanResult:
    try:
        return pipeline.scan(request)
    except HTTPException:
        raise
    except Exception:
        raise _error("detection_failed", "The detection service could not process this input.", status.HTTP_500_INTERNAL_SERVER_ERROR) from None


def _fuse(pipeline: DetectionPipeline, results: list[ScanResult]) -> ScanResult:
    try:
        return pipeline.fuse(results)
    except Exception:
        raise _error("fusion_failed", "The detection service could not combine these inputs.", status.HTTP_500_INTERNAL_SERVER_ERROR) from None


def _upload_rules(input_type: InputType) -> tuple[frozenset[str], int, str]:
    if input_type is InputType.IMAGE:
        config = ImageDetectionConfig()
        return frozenset({".png", ".jpg", ".jpeg", ".webp"}), config.max_file_bytes, "image"
    if input_type is InputType.AUDIO:
        config = AudioDetectionConfig()
        return frozenset(f".{item.lower()}" for item in config.allowed_formats), config.max_file_bytes, "audio"
    if input_type is InputType.VIDEO:
        config = VideoDetectionConfig()
        return frozenset(f".{item.lower()}" for item in config.allowed_formats), config.max_file_bytes, "video"
    raise ValueError(f"Uploads are not supported for {input_type}")


@contextmanager
def _temporary_upload(upload: UploadFile, input_type: InputType) -> Iterator[str]:
    extensions, maximum_bytes, expected_media_type = _upload_rules(input_type)
    suffix = Path(upload.filename or "").suffix.lower()
    if suffix not in extensions:
        raise _error("unsupported_file_type", f"Unsupported {input_type.value} file type.", status.HTTP_400_BAD_REQUEST)
    if upload.content_type and not upload.content_type.lower().startswith(f"{expected_media_type}/"):
        raise _error("unsupported_content_type", f"Expected an {expected_media_type} upload.", status.HTTP_400_BAD_REQUEST)
    descriptor, name = tempfile.mkstemp(prefix="truthlens_upload_", suffix=suffix)
    try:
        total = 0
        with os.fdopen(descriptor, "wb") as destination:
            while chunk := upload.file.read(1024 * 1024):
                total += len(chunk)
                if total > maximum_bytes:
                    raise _error("upload_too_large", f"{input_type.value.capitalize()} upload exceeds its size limit.", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
                destination.write(chunk)
        yield name
    finally:
        upload.file.close()
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _scan_upload(pipeline: DetectionPipeline, upload: UploadFile, input_type: InputType) -> ScanResult:
    with _temporary_upload(upload, input_type) as path:
        return _scan(pipeline, ScanRequest(input_type=input_type, content=path, mime_type=upload.content_type))
