"""Self-contained HTML renderer for AgentShield red team reports."""

from __future__ import annotations

from html import escape
from pathlib import Path

from agentshield import __version__
from agentshield.cli.certify import CertificationResult
from agentshield.cli.report import RedTeamReport
from agentshield.cli.runner import AttackResult
from agentshield.exceptions import AgentShieldError


class HtmlReportRenderer:
    """Renders a RedTeamReport as a self-contained HTML file."""

    _RATE_GREEN_THRESHOLD = 75.0
    _RATE_YELLOW_THRESHOLD = 50.0

    _OUTCOME_CLASSES: dict[str, str] = {
        "detected": "outcome-detected",
        "bypassed": "outcome-bypassed",
        "simulated": "outcome-simulated",
        "error": "outcome-error",
    }

    _SEVERITY_CLASSES: dict[str, str] = {
        "critical": "severity-critical",
        "high": "severity-high",
        "medium": "severity-medium",
        "low": "severity-low",
    }

    def __init__(self, report: RedTeamReport, cert: CertificationResult) -> None:
        """Initialize with report data and certification result.

        Args:
            report: The full red team report.
            cert: The certification result for this report.
        """
        self._report = report
        self._cert = cert

    def render(self) -> str:
        """Render the complete HTML string.

        Returns:
            A complete, self-contained HTML document as a string.
        """
        rate_class = self._rate_class(self._report.detection_rate_pct)
        certification_banner = self._render_certification_banner()
        rows_html = "\n".join(
            self._render_result_row(index, result)
            for index, result in enumerate(self._report.results, start=1)
        )

        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '  <meta charset="utf-8" />\n'
            '  <meta name="viewport" content="width=device-width, initial-scale=1" />\n'
            "  <title>AgentShield Red Team Report</title>\n"
            "  <style>\n"
            "    :root {\n"
            "      --bg: #0d1117;\n"
            "      --card: #161b22;\n"
            "      --border: #30363d;\n"
            "      --text: #e6edf3;\n"
            "      --muted: #8b949e;\n"
            "      --green: #3fb950;\n"
            "      --red: #f85149;\n"
            "      --yellow: #d29922;\n"
            "      --orange: #fb8500;\n"
            "      --gray: #9ca3af;\n"
            "    }\n"
            "    * { box-sizing: border-box; }\n"
            "    body {\n"
            "      margin: 0;\n"
            "      font-family: system-ui, -apple-system, sans-serif;\n"
            "      background: var(--bg);\n"
            "      color: var(--text);\n"
            "      line-height: 1.45;\n"
            "    }\n"
            "    .container {\n"
            "      max-width: 1200px;\n"
            "      margin: 0 auto;\n"
            "      padding: 24px 16px 40px;\n"
            "    }\n"
            "    .card {\n"
            "      background: var(--card);\n"
            "      border: 1px solid var(--border);\n"
            "      border-radius: 12px;\n"
            "      padding: 16px;\n"
            "    }\n"
            "    h1 {\n"
            "      margin: 0 0 10px;\n"
            "      font-size: 30px;\n"
            "      font-weight: 800;\n"
            "    }\n"
            "    .pills {\n"
            "      display: flex;\n"
            "      flex-wrap: wrap;\n"
            "      gap: 8px;\n"
            "    }\n"
            "    .pill {\n"
            "      display: inline-flex;\n"
            "      align-items: center;\n"
            "      border: 1px solid var(--border);\n"
            "      border-radius: 999px;\n"
            "      padding: 6px 10px;\n"
            "      font-size: 12px;\n"
            "      color: var(--muted);\n"
            "      background: rgba(22, 27, 34, 0.8);\n"
            "    }\n"
            "    .summary {\n"
            "      display: flex;\n"
            "      flex-wrap: wrap;\n"
            "      gap: 12px;\n"
            "      margin-top: 16px;\n"
            "    }\n"
            "    .summary-card {\n"
            "      flex: 1 1 220px;\n"
            "      min-height: 92px;\n"
            "      display: flex;\n"
            "      flex-direction: column;\n"
            "      justify-content: center;\n"
            "      gap: 4px;\n"
            "    }\n"
            "    .summary-label {\n"
            "      color: var(--muted);\n"
            "      font-size: 12px;\n"
            "      text-transform: uppercase;\n"
            "      letter-spacing: 0.06em;\n"
            "    }\n"
            "    .summary-value {\n"
            "      font-size: 28px;\n"
            "      font-weight: 800;\n"
            "    }\n"
            "    .text-green { color: var(--green); }\n"
            "    .text-red { color: var(--red); }\n"
            "    .text-yellow { color: var(--yellow); }\n"
            "    .banner {\n"
            "      margin-top: 16px;\n"
            "      border-left: 4px solid var(--green);\n"
            "    }\n"
            "    .banner.warning {\n"
            "      border-left-color: var(--red);\n"
            "    }\n"
            "    .banner h2 {\n"
            "      margin: 0 0 6px;\n"
            "      font-size: 22px;\n"
            "      font-weight: 800;\n"
            "    }\n"
            "    .banner p {\n"
            "      margin: 0;\n"
            "      color: var(--muted);\n"
            "    }\n"
            "    .table-wrap {\n"
            "      margin-top: 16px;\n"
            "      overflow-x: auto;\n"
            "    }\n"
            "    table {\n"
            "      width: 100%;\n"
            "      border-collapse: collapse;\n"
            "      min-width: 900px;\n"
            "    }\n"
            "    thead th {\n"
            "      text-align: left;\n"
            "      padding: 10px 12px;\n"
            "      font-size: 13px;\n"
            "      color: var(--muted);\n"
            "      border-bottom: 1px solid var(--border);\n"
            "      cursor: pointer;\n"
            "      user-select: none;\n"
            "      white-space: nowrap;\n"
            "    }\n"
            '    thead th.sorted-asc::after { content: "  ▲"; }\n'
            '    thead th.sorted-desc::after { content: "  ▼"; }\n'
            "    tbody td {\n"
            "      padding: 10px 12px;\n"
            "      border-bottom: 1px solid #21262d;\n"
            "      vertical-align: top;\n"
            "    }\n"
            "    tbody tr:hover { background: rgba(63, 185, 80, 0.08); }\n"
            "    .outcome-detected { color: var(--green); font-weight: 700; }\n"
            "    .outcome-bypassed { color: var(--red); font-weight: 700; }\n"
            "    .outcome-simulated { color: var(--gray); font-weight: 700; }\n"
            "    .outcome-error { color: var(--yellow); font-weight: 700; }\n"
            "    .severity-critical { color: var(--red); font-weight: 700; }\n"
            "    .severity-high { color: var(--orange); font-weight: 700; }\n"
            "    .severity-medium { color: var(--yellow); font-weight: 700; }\n"
            "    .severity-low { color: var(--green); font-weight: 700; }\n"
            "    footer {\n"
            "      margin-top: 20px;\n"
            "      color: var(--muted);\n"
            "      font-size: 12px;\n"
            "      text-align: right;\n"
            "    }\n"
            "    @media (max-width: 860px) {\n"
            "      h1 { font-size: 24px; }\n"
            "      .summary-value { font-size: 24px; }\n"
            "      .container { padding: 16px 12px 30px; }\n"
            "    }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            '  <main class="container">\n'
            '    <section class="card">\n'
            "      <h1>&#x1F6E1; AgentShield Red Team Report</h1>\n"
            '      <div class="pills">\n'
            f'        <span class="pill">Agent: {escape(self._report.agent_module)}</span>\n'
            f'        <span class="pill">Policy: {escape(self._report.policy)}</span>\n'
            f'        <span class="pill">Run: {escape(self._report.run_timestamp)}</span>\n'
            "      </div>\n"
            "    </section>\n"
            "\n"
            '    <section class="summary">\n'
            '      <article class="card summary-card">\n'
            '        <div class="summary-label">Total Attacks</div>\n'
            f'        <div class="summary-value">{self._report.total_attacks}</div>\n'
            "      </article>\n"
            '      <article class="card summary-card">\n'
            '        <div class="summary-label">Detected</div>\n'
            f'        <div class="summary-value text-green">{self._report.detected_count}</div>\n'
            "      </article>\n"
            '      <article class="card summary-card">\n'
            '        <div class="summary-label">Bypassed</div>\n'
            f'        <div class="summary-value text-red">{self._report.bypassed_count}</div>\n'
            "      </article>\n"
            '      <article class="card summary-card">\n'
            '        <div class="summary-label">Detection Rate</div>\n'
            f'        <div class="summary-value {rate_class}">{self._report.detection_rate_pct:.2f}%</div>\n'
            "      </article>\n"
            "    </section>\n"
            "\n"
            f"    {certification_banner}\n"
            "\n"
            '    <section class="card table-wrap">\n'
            '      <table id="results-table">\n'
            "        <thead>\n"
            "          <tr>\n"
            '            <th data-type="number">#</th>\n'
            '            <th data-type="text">Attack ID</th>\n'
            '            <th data-type="text">Name</th>\n'
            '            <th data-type="text">Category</th>\n'
            '            <th data-type="text">Severity</th>\n'
            '            <th data-type="text">Outcome</th>\n'
            '            <th data-type="number">Latency (ms)</th>\n'
            "          </tr>\n"
            "        </thead>\n"
            "        <tbody>\n"
            f"{rows_html}\n"
            "        </tbody>\n"
            "      </table>\n"
            "    </section>\n"
            "\n"
            "    <footer>\n"
            f"      Generated by AgentShield v{escape(__version__)} &#8226; {escape(self._cert.cert_timestamp)}\n"
            "    </footer>\n"
            "  </main>\n"
            "\n"
            "  <script>\n"
            "    (() => {\n"
            "      const table = document.getElementById('results-table');\n"
            "      if (!table) {\n"
            "        return;\n"
            "      }\n"
            "\n"
            "      const body = table.tBodies[0];\n"
            "      const headers = Array.from(table.querySelectorAll('thead th'));\n"
            "      const sortState = new Map();\n"
            "\n"
            "      headers.forEach((header, index) => {\n"
            "        header.addEventListener('click', () => {\n"
            "          const current = sortState.get(index) === 'asc' ? 'desc' : 'asc';\n"
            "          sortState.clear();\n"
            "          sortState.set(index, current);\n"
            "\n"
            "          const rows = Array.from(body.querySelectorAll('tr'));\n"
            "          const type = header.getAttribute('data-type') || 'text';\n"
            "\n"
            "          rows.sort((rowA, rowB) => {\n"
            "            const cellA = rowA.children[index];\n"
            "            const cellB = rowB.children[index];\n"
            "            const valueA = (cellA.getAttribute('data-sort') || cellA.textContent || '').trim();\n"
            "            const valueB = (cellB.getAttribute('data-sort') || cellB.textContent || '').trim();\n"
            "\n"
            "            let comparison = 0;\n"
            "            if (type === 'number') {\n"
            "              comparison = Number(valueA) - Number(valueB);\n"
            "            } else {\n"
            "              comparison = valueA.localeCompare(valueB, undefined, { sensitivity: 'base' });\n"
            "            }\n"
            "\n"
            "            return current === 'asc' ? comparison : -comparison;\n"
            "          });\n"
            "\n"
            "          rows.forEach((row) => body.appendChild(row));\n"
            "          headers.forEach((item) => {\n"
            "            item.classList.remove('sorted-asc');\n"
            "            item.classList.remove('sorted-desc');\n"
            "          });\n"
            "          header.classList.add(current === 'asc' ? 'sorted-asc' : 'sorted-desc');\n"
            "        });\n"
            "      });\n"
            "    })();\n"
            "  </script>\n"
            "</body>\n"
            "</html>\n"
        )

    @staticmethod
    def save(html: str, path: Path) -> None:
        """Write the rendered HTML to a file.

        Args:
            html: The rendered HTML string.
            path: Output path.

        Raises:
            AgentShieldError: If the file cannot be written.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{html}\n", encoding="utf-8")
        except OSError as exc:
            raise AgentShieldError(f"Failed to write HTML report to '{path}': {exc}") from exc

    def _render_certification_banner(self) -> str:
        """Render certification banner HTML.

        Returns:
            Banner section markup.
        """
        if self._cert.is_certified:
            tier_label = escape(self._cert.tier.value.upper())
            return (
                '<section class="card banner">\n'
                f'  <h2 style="color: {escape(self._cert.badge_color_hex)};">'
                f"{tier_label} Certification Earned</h2>\n"
                "  <p>Congratulations. This agent cleared AgentShield certification "
                "thresholds for the tested attack suite.</p>\n"
                "</section>"
            )

        return (
            '<section class="card banner warning">\n'
            '  <h2 class="text-red">&#9888; Not Certified</h2>\n'
            "  <p>Detection rate is below 50%. Improve policy strictness, detector "
            "coverage, and runtime hardening before requesting certification.</p>\n"
            "</section>"
        )

    def _render_result_row(self, index: int, result: AttackResult) -> str:
        """Render one result table row.

        Args:
            index: 1-based row index.
            result: Attack result row.

        Returns:
            HTML table row markup.
        """
        severity = result.severity.value
        outcome = result.outcome.value
        severity_class = self._SEVERITY_CLASSES.get(severity, "")
        outcome_class = self._OUTCOME_CLASSES.get(outcome, "")

        return (
            "          <tr>\n"
            f'            <td data-sort="{index}">{index}</td>\n'
            f'            <td data-sort="{escape(result.attack_id)}">{escape(result.attack_id)}</td>\n'
            f'            <td data-sort="{escape(result.attack_name)}">{escape(result.attack_name)}</td>\n'
            f'            <td data-sort="{escape(result.category.value)}">{escape(result.category.value)}</td>\n'
            f'            <td data-sort="{escape(severity)}" class="{severity_class}">{escape(severity)}</td>\n'
            f'            <td data-sort="{escape(outcome)}" class="{outcome_class}">{escape(outcome)}</td>\n'
            f'            <td data-sort="{result.latency_ms:.4f}">{result.latency_ms:.2f}</td>\n'
            "          </tr>"
        )

    @staticmethod
    def _rate_class(rate: float) -> str:
        """Return CSS class for detection rate card color.

        Args:
            rate: Detection rate percentage.

        Returns:
            CSS class name.
        """
        if rate >= HtmlReportRenderer._RATE_GREEN_THRESHOLD:
            return "text-green"
        if rate >= HtmlReportRenderer._RATE_YELLOW_THRESHOLD:
            return "text-yellow"
        return "text-red"
