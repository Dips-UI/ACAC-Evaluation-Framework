import unittest
from decimal import Decimal
from acac.adjudication import validate_adjudication, validate_ai_audit


class AdjudicationTests(unittest.TestCase):
    def test_roles_are_artifact_specific(self):
        base = {"review_id": "a", "case_id": "c", "reviewer_role": "adjudicator", "source_case_hash": "sha256:" + "0" * 64, "authorization_spec_hash": "sha256:" + "1" * 64, "reference_content_hash": "sha256:" + "2" * 64, "considered_review_hashes": ["sha256:" + "3" * 64], "disagreement_disposition": [{"case_id": "c", "disposition": "accepted", "reason": "reason"}], "decision_rationale": "reason", "adjudicator_id": "human", "independence_declaration": True, "independence_basis": "independent", "completed_at": "2026-01-01T00:00:00Z"}
        validate_adjudication(base)
        with self.assertRaises(ValueError): validate_ai_audit({"reviewer_role": "ai_auditor", "model_metadata": {"provider": "x"}})
        with self.assertRaises(ValueError): validate_adjudication({**base, "reviewer_role": "human_reviewer"})

    def test_ai_audit_validates_prompt_hash_and_exact_settings_types(self):
        from acac.adjudication import AdjudicationError
        valid = {"reviewer_role": "ai_auditor", "model_metadata": {"provider": "p", "family": "f", "model_id": "m", "version": "v", "runtime_version": "r", "prompt_hash": "sha256:" + "a" * 64, "settings": {"nested": [True, 2, Decimal("0.125")]}, "run_timestamp": "2026-01-01T00:00:00Z"}}
        validate_ai_audit(valid)
        for settings in ({"x": None}, {"x": 1.5}, {"x": 2**63}, {"x": Decimal("NaN")}):
            candidate = {**valid, "model_metadata": {**valid["model_metadata"], "settings": settings}}
            with self.subTest(settings=settings), self.assertRaises(AdjudicationError):
                validate_ai_audit(candidate)
        candidate = {**valid, "model_metadata": {**valid["model_metadata"], "prompt_hash": "sha256:" + "g" * 64}}
        with self.assertRaises(AdjudicationError):
            validate_ai_audit(candidate)


if __name__ == "__main__": unittest.main()
