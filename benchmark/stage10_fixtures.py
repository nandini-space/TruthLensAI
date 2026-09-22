"""Deterministic, synthetic inputs shared by Stage 10 validation tools.

These strings are intentionally fictional and are not connected to real
organizations, credentials, infrastructure, or victims.
"""

BENIGN_TEXTS = (
    "Could you bring the meeting notes to our 3 PM planning session?",
    "Your Example Services account statement is ready in the official app.",
    "Invoice 1042 has been approved and will be paid on Friday.",
    "The library will close at 6 PM today for routine maintenance.",
)

BENIGN_URLS = (
    "https://www.example.com/",
    "https://www.example.org/news",
    "https://portal.example.net/search?q=quarterly+report&page=2",
)

THREAT_TEXTS = {
    "phishing": "Demo Bank account suspended. Verify your password immediately to restore access.",
    "scam": "You won a demo prize. Send a processing payment today to receive it.",
    "social_engineering": "Keep this private, act now, and move our conversation to an encrypted chat app.",
}

SUSPICIOUS_URLS = (
    "http://198.51.100.42/login",
    "https://demo:password@safe-example.test/verify",
    "https://login.example.test/verify?redirect=https%3A%2F%2Fother.example",
    "https://safe-example.test/%76%65%72%69%66%79%2F%6C%6F%67%69%6E",
    "https://paypal-security.example.test/login",
)

IMAGE_BENIGN_TEXT = BENIGN_TEXTS[0]
IMAGE_THREAT_TEXT = THREAT_TEXTS["phishing"]
AUDIO_THREAT_TEXT = THREAT_TEXTS["phishing"]
VIDEO_THREAT_TEXT = THREAT_TEXTS["phishing"]
