"""Explainable contextual signal rules for the text detector."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..schemas import Signal


@dataclass(frozen=True, slots=True)
class SignalRule:
    code: str
    description: str
    pattern: re.Pattern[str]
    strength: int


def _pattern(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


SIGNAL_RULES: tuple[SignalRule, ...] = (
    SignalRule("urgency", "Urgency or time-pressure language was detected.", _pattern(r"\b(urgent|immediately|act now|within \d+ (?:hours?|minutes?)|last chance|(?:will be|has been) (?:blocked|suspended) today)\b"), 8),
    SignalRule("account_verification", "An account verification request was detected.", _pattern(r"\b(?:verify|confirm|validate) (?:your )?(?:account|identity)\b|\baccount (?:verification|has been (?:suspended|blocked))\b"), 12),
    SignalRule("credential_request", "A request for account credentials was detected.", _pattern(r"\b(?:enter|provide|share|send|confirm|verify) (?:your )?(?:password|login|credentials?)\b"), 35),
    SignalRule("otp_request", "A request for a one-time password or verification code was detected.", _pattern(r"\b(?:send|share|provide|reply with|give) (?:the )?(?:otp|one[ -]?time (?:password|code)|verification code)\b"), 35),
    SignalRule("financial_request", "A request for money or payment was detected.", _pattern(r"\b(?:pay|transfer|send) (?:the )?(?:processing fee|fee|money|payment)|\bprocessing fee\b"), 22),
    SignalRule("prize_claim", "A prize, reward, or winnings claim was detected.", _pattern(r"\b(?:congratulations|you (?:have )?won|claim your (?:prize|reward)|lottery)\b"), 24),
    SignalRule("impersonation", "Possible organization or support impersonation language was detected.", _pattern(r"\b(?:bank|support team|security team|customer care) (?:team )?(?:has|is|requires|requests)\b"), 10),
    SignalRule("threat", "Threatening or coercive language was detected.", _pattern(r"\b(?:we will|i will) (?:expose|publish|harm|report|ruin)|\bunless you\b"), 40),
    SignalRule("secrecy_request", "A request to keep the matter secret was detected.", _pattern(r"\b(?:do not tell|keep (?:this )?(?:secret|confidential)|don't tell)\b"), 10),
    SignalRule("sensitive_information_request", "A request for sensitive personal or financial information was detected.", _pattern(r"\b(?:share|send|provide) (?:your )?(?:aadhaar|ssn|cvv|card number|bank details)\b"), 30),
    SignalRule("pressure", "Manipulative pressure language was detected.", _pattern(r"\b(?:limited time|avoid (?:suspension|blocking)|final warning|must respond)\b"), 8),
    SignalRule("employment_or_investment_claim", "A potentially risky employment or investment claim was detected.", _pattern(r"\b(?:guaranteed returns?|double your money|earn \$?\d+|investment opportunity|work from home and earn)\b"), 14),
    SignalRule("move_platform_request", "A request to move the conversation to another platform was detected.", _pattern(r"\b(?:move|continue|contact) (?:on|via) (?:whatsapp|telegram|signal)\b"), 8),
)

_SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}


def detect_signals(analysis_text: str, domains: list[str]) -> list[Signal]:
    """Return one evidence-backed signal per matched rule."""
    signals: list[Signal] = []
    for rule in SIGNAL_RULES:
        match = rule.pattern.search(analysis_text)
        if match:
            signals.append(
                Signal(
                    code=rule.code,
                    description=rule.description,
                    source="text_rule",
                    details={"evidence": match.group(0), "strength": rule.strength},
                )
            )
    for domain in domains:
        if domain in _SHORTENER_DOMAINS:
            signals.append(
                Signal(
                    code="shortened_url",
                    description="A shortened URL was detected.",
                    source="entity_rule",
                    details={"evidence": domain, "strength": 8},
                )
            )
            break
    return signals
