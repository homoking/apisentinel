from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from apisentinel.scanner.models import ScanResult


def result_to_json(result: ScanResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2)


def result_to_markdown(result: ScanResult) -> str:
    lines = [
        f"# APISentinel Report: {result.target}",
        "",
        f"- Scan ID: `{result.id}`",
        f"- Created: {result.created_at.isoformat()}",
        f"- Security Score: **{result.summary.score}/100**",
        f"- Findings: **{result.summary.findings_count}**",
        "",
        "## Severity Distribution",
        "",
    ]
    for severity, count in result.summary.severity_distribution.items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings detected.")
    for finding in result.findings:
        location = f" `{finding.method} {finding.endpoint}`" if finding.endpoint else ""
        lines.extend(
            [
                f"### {finding.title}{location}",
                "",
                f"- Severity: **{finding.severity.value.upper()}**",
                f"- Rule: `{finding.rule_id}`",
                f"- Description: {finding.description}",
                f"- Why it matters: {finding.why_it_matters}",
            ]
        )
        if finding.ai:
            lines.extend(
                [
                    "",
                    "**AI Security Analysis**",
                    "",
                    f"- Explanation: {finding.ai.explanation}",
                    f"- Attack scenario: {finding.ai.attack_scenario}",
                    f"- Recommended fix: {finding.ai.recommended_fix}",
                ]
            )
        lines.append("")
    return "\n".join(lines)


def result_to_html(result: ScanResult) -> str:
    env = Environment(
        loader=PackageLoader("apisentinel.dashboard", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    return template.render(result=result)


def write_report(result: ScanResult, fmt: str, output: Path) -> Path:
    fmt = fmt.lower()
    if fmt == "json":
        content = result_to_json(result)
    elif fmt in {"md", "markdown"}:
        content = result_to_markdown(result)
    elif fmt == "html":
        content = result_to_html(result)
    else:
        raise ValueError("Format must be one of: json, markdown, html")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content)
    return output
