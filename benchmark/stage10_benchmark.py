"""Small local latency sampler for the deterministic Module 1 paths.

Run with: .venv\\Scripts\\python.exe benchmark/stage10_benchmark.py
"""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

from backend.detection.multimodal_fusion import MultimodalFusion
from backend.detection.schemas import InputType, ScanRequest
from backend.detection.text_detector import TextDetector
from backend.detection.url_detector import UrlDetector
from benchmark.stage10_fixtures import SUSPICIOUS_URLS, THREAT_TEXTS


def sample(name: str, action, iterations: int = 10) -> None:
    timings = []
    for _ in range(iterations):
        started = time.perf_counter(); action(); timings.append((time.perf_counter() - started) * 1000)
    print(f"{name}: avg={statistics.fmean(timings):.3f} ms min={min(timings):.3f} ms max={max(timings):.3f} ms n={iterations}")


def main() -> None:
    text = TextDetector(); url = UrlDetector()
    text_request = ScanRequest(input_type=InputType.TEXT, content=THREAT_TEXTS["phishing"])
    url_request = ScanRequest(input_type=InputType.URL, content=SUSPICIOUS_URLS[0])
    text_result, url_result = text.detect(text_request), url.detect(url_request)
    sample("text", lambda: text.detect(text_request))
    sample("url", lambda: url.detect(url_request))
    sample("multimodal_fusion", lambda: MultimodalFusion().fuse([text_result, url_result]))
    print("Image/OCR, audio/STT, and video decode are excluded: local model binaries/configuration are intentionally not provisioned by this benchmark.")


if __name__ == "__main__": main()
