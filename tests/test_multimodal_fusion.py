import unittest

from backend.detection.ai_analyzer import AIReasoner
from backend.detection.multimodal_fusion import MultimodalFusion
from backend.detection.schemas import InputType, ScanResult, Severity, Signal, ThreatType


def result(modality, score=75, threat=ThreatType.PHISHING, signals=("credential_request",), confidence=.8):
    return ScanResult(input_type=modality, risk_score=score, severity=Severity.CRITICAL if score >= 70 else Severity.MODERATE, threat_type=threat, confidence=confidence, signals=[Signal(code=code, description=code, source="child") for code in signals], explanation="Child.", recommendation="Verify.", metadata={"assessment_status": "completed"})


class MultimodalFusionTests(unittest.TestCase):
    def setUp(self): self.fusion = MultimodalFusion()

    def test_single_modal_results_remain_equivalent(self):
        child = result(InputType.URL, 80, ThreatType.PHISHING)
        fused = self.fusion.fuse([child])
        self.assertEqual((fused.input_type, fused.risk_score, fused.threat_type), (InputType.URL, 80, ThreatType.PHISHING))

    def test_text_url_independent_corroboration_is_bounded(self):
        fused = self.fusion.fuse([result(InputType.TEXT, 75, signals=("urgency",)), result(InputType.URL, 80, signals=("credential_request",))])
        self.assertEqual(fused.risk_score, 85)
        self.assertEqual(fused.input_type, InputType.URL)
        self.assertEqual(fused.threat_type, ThreatType.PHISHING)
        self.assertEqual(fused.metadata["corroborating_modalities"], ["text"])

    def test_fused_severity_uses_existing_deterministic_thresholds(self):
        fused = self.fusion.fuse([result(InputType.TEXT, 75, signals=("urgency",)), result(InputType.URL, 80, signals=("credential_request",))])
        self.assertEqual(fused.severity, Severity.CRITICAL)

    def test_duplicate_evidence_does_not_add_risk(self):
        fused = self.fusion.fuse([result(InputType.IMAGE, 75, signals=("urgency",)), result(InputType.AUDIO, 75, signals=("urgency",))])
        self.assertEqual(fused.risk_score, 75)
        self.assertEqual(fused.metadata["deduplicated_evidence_count"], 1)

    def test_conflicts_preserve_strongest_and_are_recorded(self):
        fused = self.fusion.fuse([result(InputType.TEXT, 80, ThreatType.PHISHING), result(InputType.URL, 20, ThreatType.SUSPICIOUS, ("url_shortener",))])
        self.assertEqual(fused.threat_type, ThreatType.PHISHING)
        self.assertIn("suspicious", fused.metadata["conflicting_threat_types"])

    def test_risk_and_confidence_are_bounded(self):
        children = [result(InputType.TEXT, 99, signals=("a",)), result(InputType.URL, 99, signals=("b",)), result(InputType.IMAGE, 99, signals=("c",)), result(InputType.AUDIO, 99, signals=("d",)), result(InputType.VIDEO, 99, signals=("e",))]
        fused = self.fusion.fuse(children)
        self.assertLessEqual(fused.risk_score, 100)
        self.assertLessEqual(fused.confidence, 1)

    def test_unknown_and_empty_inputs_are_safe(self):
        unknown = ScanResult(input_type=InputType.AUDIO, risk_score=None, severity=Severity.UNKNOWN, threat_type=ThreatType.UNKNOWN, confidence=None, explanation="No audio.", recommendation="Verify.")
        self.assertEqual(self.fusion.fuse([]).threat_type, ThreatType.UNKNOWN)
        self.assertEqual(self.fusion.fuse([unknown]).metadata["fusion_status"], "no_meaningful_evidence")

    def test_deterministic_repeated_results_and_ai_compatibility(self):
        children = [result(InputType.TEXT, signals=("urgency",)), result(InputType.IMAGE, signals=("credential_request",))]
        first, second = self.fusion.fuse(children), self.fusion.fuse(children)
        self.assertEqual((first.risk_score, first.signals), (second.risk_score, second.signals))
        self.assertEqual(AIReasoner().enrich(first).risk_score, first.risk_score)
