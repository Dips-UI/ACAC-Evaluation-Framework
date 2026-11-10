"""Read-only v1 naming/version consistency checks."""


EXPECTED = {"case_schema": "acac-1.3", "manifest": "1.3", "grader": "acac-grader-1.3", "auth_non_temporal": "acac-auth-1.0", "auth_temporal": "acac-auth-1.1"}


def check_versions(*, case_schema: str, manifest: str, grader: str, auth_non_temporal: str, auth_temporal: str) -> None:
    actual = {"case_schema": case_schema, "manifest": manifest, "grader": grader, "auth_non_temporal": auth_non_temporal, "auth_temporal": auth_temporal}
    if actual != EXPECTED:
        raise ValueError("version_contract_mismatch")
