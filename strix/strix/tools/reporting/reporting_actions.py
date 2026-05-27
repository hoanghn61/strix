import ast
import contextlib
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Placeholder patterns that indicate the agent did not actually run the PoC
_PLACEHOLDER_PATTERNS = re.compile(
    r"^(n/?a|none|null|todo|tbd|placeholder|<.*?>|\[.*?\]|not\s+run|not\s+tested|"
    r"pending|unknown|insert\s+output|paste\s+output|output\s+here|see\s+poc)$",
    re.IGNORECASE,
)


_CVSS_FIELDS = (
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
)


def parse_cvss_xml(xml_str: str) -> dict[str, str] | None:
    if not xml_str or not xml_str.strip():
        return None
    result = {}
    for field in _CVSS_FIELDS:
        match = re.search(rf"<{field}>(.*?)</{field}>", xml_str, re.DOTALL)
        if match:
            result[field] = match.group(1).strip()
    return result if result else None


def parse_code_locations_xml(xml_str: str) -> list[dict[str, Any]] | None:
    if not xml_str or not xml_str.strip():
        return None
    locations = []
    for loc_match in re.finditer(r"<location>(.*?)</location>", xml_str, re.DOTALL):
        loc: dict[str, Any] = {}
        loc_content = loc_match.group(1)
        for field in (
            "file",
            "start_line",
            "end_line",
            "snippet",
            "label",
            "fix_before",
            "fix_after",
        ):
            field_match = re.search(rf"<{field}>(.*?)</{field}>", loc_content, re.DOTALL)
            if field_match:
                raw = field_match.group(1)
                value = (
                    raw.strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else raw.strip()
                )
                if field in ("start_line", "end_line"):
                    with contextlib.suppress(ValueError, TypeError):
                        loc[field] = int(value)
                elif value:
                    loc[field] = value
        if loc.get("file") and loc.get("start_line") is not None:
            locations.append(loc)
    return locations if locations else None


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def calculate_cvss_and_severity(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        c = CVSS3(vector)
        scores = c.scores()
        severities = c.severities()

        base_score = scores[0]
        base_severity = severities[0]

        severity = base_severity.lower()

    except Exception:
        import logging

        logging.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return base_score, severity, vector


def _validate_required_fields(**kwargs: str | None) -> list[str]:
    validation_errors: list[str] = []

    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
        "remediation_steps": "Remediation steps cannot be empty",
        "confirmed_output": (
            "confirmed_output is REQUIRED - paste the actual response/terminal "
            "output observed during exploitation that proves this vulnerability is real"
        ),
    }

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            validation_errors.append(error_msg)

    return validation_errors


def _validate_confirmed_output(output: str) -> list[str]:
    """Ensure confirmed_output is substantive evidence, not a placeholder."""
    errors: list[str] = []
    stripped = output.strip()

    if len(stripped) < 50:
        errors.append(
            "confirmed_output is too short (< 50 chars) — paste the actual "
            "HTTP response body, terminal output, or error message observed "
            "during exploitation"
        )
        return errors

    if _PLACEHOLDER_PATTERNS.match(stripped):
        errors.append(
            f"confirmed_output looks like a placeholder ('{stripped[:40]}') — "
            "provide the real observed output that confirms exploitation"
        )

    return errors


def _validate_poc_code_quality(code: str) -> list[str]:
    """Validate the PoC is real executable code, not pseudocode or a placeholder."""
    warnings: list[str] = []
    stripped = code.strip()

    if len(stripped) < 20:
        warnings.append(
            "poc_script_code is too short — provide a complete exploit "
            "script or request payload, not a one-liner placeholder"
        )
        return warnings

    # Try to parse as Python; if it fails, it might be shell/curl — just log
    try:
        ast.parse(stripped)
    except SyntaxError:
        # Not Python — could be bash/curl/HTTP raw. Check if it's obviously pseudocode.
        pseudocode_markers = re.compile(
            r"^(#.*|//.*|/\*.*|\.\.\.|<TODO>|<PAYLOAD>|INSERT HERE|EXPLOIT HERE)",
            re.IGNORECASE | re.MULTILINE,
        )
        non_comment_lines = [
            ln for ln in stripped.splitlines() if ln.strip() and not ln.strip().startswith("#")
        ]
        if not non_comment_lines:
            warnings.append(
                "poc_script_code appears to contain only comments — provide "
                "executable code, curl commands, or HTTP request payload"
            )
        elif all(pseudocode_markers.match(ln.strip()) for ln in non_comment_lines[:5]):
            warnings.append(
                "poc_script_code looks like pseudocode — replace with "
                "runnable exploit code or raw HTTP request"
            )

    return warnings


def _validate_proxy_evidence(evidence_proxy_ids: str) -> tuple[list[str], list[str]]:
    """Soft-validate that provided Caido proxy IDs actually exist.

    Returns (errors, warnings). Errors if the format is invalid.
    Warnings if proxy is unreachable but IDs were provided.
    """
    errors: list[str] = []
    warnings: list[str] = []

    ids = [i.strip() for i in evidence_proxy_ids.split(",") if i.strip()]
    if not ids:
        errors.append(
            "evidence_proxy_ids was provided but is empty after parsing — "
            "use comma-separated Caido request IDs (e.g. 'req_abc123,req_def456')"
        )
        return errors, warnings

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
        missing_ids: list[str] = []
        for req_id in ids[:5]:  # check up to 5 IDs to avoid slowdown
            result = manager.view_request(req_id, "request")
            if result.get("error") or not result.get("request"):
                missing_ids.append(req_id)

        if missing_ids:
            errors.append(
                f"The following evidence_proxy_ids were not found in Caido proxy: "
                f"{missing_ids}. Ensure you reference real captured request IDs."
            )
    except Exception as exc:
        warnings.append(
            f"Could not verify evidence_proxy_ids against proxy (proxy may be unavailable): {exc}"
        )

    return errors, warnings


def _validate_cvss_parameters(**kwargs: str) -> list[str]:
    validation_errors: list[str] = []

    cvss_validations = {
        "attack_vector": ["N", "A", "L", "P"],
        "attack_complexity": ["L", "H"],
        "privileges_required": ["N", "L", "H"],
        "user_interaction": ["N", "R"],
        "scope": ["U", "C"],
        "confidentiality": ["N", "L", "H"],
        "integrity": ["N", "L", "H"],
        "availability": ["N", "L", "H"],
    }

    for param_name, valid_values in cvss_validations.items():
        value = kwargs.get(param_name)
        if value not in valid_values:
            validation_errors.append(
                f"Invalid {param_name}: {value}. Must be one of: {valid_values}"
            )

    return validation_errors


@register_tool(sandbox_execution=False)
def create_vulnerability_report(  # noqa: PLR0912
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    confirmed_output: str,
    remediation_steps: str,
    cvss_breakdown: str,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: str | None = None,
    evidence_proxy_ids: str | None = None,
) -> dict[str, Any]:
    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        confirmed_output=confirmed_output,
        remediation_steps=remediation_steps,
    )

    # Validate confirmed_output is substantive evidence
    if confirmed_output and confirmed_output.strip():
        validation_errors.extend(_validate_confirmed_output(confirmed_output))

    # Validate PoC code quality (non-fatal warnings become errors to force real PoCs)
    if poc_script_code and poc_script_code.strip():
        poc_quality_issues = _validate_poc_code_quality(poc_script_code)
        validation_errors.extend(poc_quality_issues)

    # Soft-validate proxy evidence IDs if provided
    evidence_warnings: list[str] = []
    if evidence_proxy_ids and evidence_proxy_ids.strip():
        proxy_errors, evidence_warnings = _validate_proxy_evidence(evidence_proxy_ids)
        validation_errors.extend(proxy_errors)
    elif not evidence_proxy_ids:
        # Not hard-blocking, but flag that proxy evidence was not provided
        logger.warning(
            "create_vulnerability_report called without evidence_proxy_ids — "
            "strongly recommend attaching Caido request IDs as evidence"
        )

    parsed_cvss = parse_cvss_xml(cvss_breakdown)
    if not parsed_cvss:
        validation_errors.append("cvss: could not parse CVSS breakdown XML")
    else:
        validation_errors.extend(_validate_cvss_parameters(**parsed_cvss))

    parsed_locations = parse_code_locations_xml(code_locations) if code_locations else None

    if parsed_locations:
        validation_errors.extend(_validate_code_locations(parsed_locations))
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            validation_errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            validation_errors.append(cwe_err)

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    assert parsed_cvss is not None
    cvss_score, severity, cvss_vector = calculate_cvss_and_severity(**parsed_cvss)

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            from strix.llm.dedupe import check_duplicate

            existing_reports = tracer.get_existing_vulnerabilities()

            candidate = {
                "title": title,
                "description": description,
                "impact": impact,
                "target": target,
                "technical_analysis": technical_analysis,
                "poc_description": poc_description,
                "poc_script_code": poc_script_code,
                "confirmed_output": confirmed_output,
                "endpoint": endpoint,
                "method": method,
            }

            dedupe_result = check_duplicate(candidate, existing_reports)

            if dedupe_result.get("dedup_check_skipped"):
                logger.warning(
                    "Deduplication check was skipped due to an error — "
                    "accepting finding but it may be a duplicate: %s",
                    dedupe_result.get("reason"),
                )

            if dedupe_result.get("is_duplicate"):
                duplicate_id = dedupe_result.get("duplicate_id", "")

                duplicate_title = ""
                for report in existing_reports:
                    if report.get("id") == duplicate_id:
                        duplicate_title = report.get("title", "Unknown")
                        break

                return {
                    "success": False,
                    "message": (
                        f"Potential duplicate of '{duplicate_title}' "
                        f"(id={duplicate_id[:8]}...). Do not re-report the same vulnerability."
                    ),
                    "duplicate_of": duplicate_id,
                    "duplicate_title": duplicate_title,
                    "confidence": dedupe_result.get("confidence", 0.0),
                    "reason": dedupe_result.get("reason", ""),
                }

            report_id = tracer.add_vulnerability_report(
                title=title,
                description=description,
                severity=severity,
                impact=impact,
                target=target,
                technical_analysis=technical_analysis,
                poc_description=poc_description,
                poc_script_code=poc_script_code,
                confirmed_output=confirmed_output,
                evidence_proxy_ids=evidence_proxy_ids,
                remediation_steps=remediation_steps,
                cvss=cvss_score,
                cvss_breakdown=parsed_cvss,
                endpoint=endpoint,
                method=method,
                cve=cve,
                cwe=cwe,
                code_locations=parsed_locations,
            )

            result: dict[str, Any] = {
                "success": True,
                "message": f"Vulnerability report '{title}' created successfully",
                "report_id": report_id,
                "severity": severity,
                "cvss_score": cvss_score,
            }
            if evidence_warnings:
                result["evidence_warnings"] = evidence_warnings
            return result

        import logging

        logging.warning("Current tracer not available - vulnerability report not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
    else:
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created (not persisted)",
            "warning": "Report could not be persisted - tracer unavailable",
        }
