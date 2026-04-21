"""
AutoShield - PDF Incident Report Generator
One-click compliance report using ReportLab (free).
Generates professional PDF: executive summary + attack table + CVE cards + recommendations.
"""

import os
import json
import logging
from datetime import datetime
from collections import defaultdict, Counter

log = logging.getLogger("AutoShield.Report")

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
        PageBreak,
        KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False
    log.warning("reportlab not installed. Run: pip install reportlab")


# ─── Color palette ────────────────────────────────────────────────────────────

if REPORTLAB_OK:
    C_BG = colors.HexColor("#0d1117")
    C_SURFACE = colors.HexColor("#161b22")
    C_BORDER = colors.HexColor("#30363d")
    C_RED = colors.HexColor("#ef4444")
    C_ORANGE = colors.HexColor("#f97316")
    C_YELLOW = colors.HexColor("#eab308")
    C_GREEN = colors.HexColor("#22c55e")
    C_BLUE = colors.HexColor("#3b82f6")
    C_TEXT = colors.HexColor("#e6edf3")
    C_MUTED = colors.HexColor("#8b949e")
    C_WHITE = colors.white

    SEV_COLORS = {
        "CRITICAL": C_RED,
        "HIGH": C_ORANGE,
        "MEDIUM": C_YELLOW,
        "LOW": C_GREEN,
    }
else:
    C_BG = C_SURFACE = C_BORDER = None
    C_RED = C_ORANGE = C_YELLOW = C_GREEN = C_BLUE = None
    C_TEXT = C_MUTED = C_WHITE = None
    SEV_COLORS = {}


# ─── Report builder ───────────────────────────────────────────────────────────


def generate_report(
    attack_events: list[dict],
    blocked_ips: list[dict],
    output_path: str = "/tmp/autoshield_report.pdf",
    org_name: str = "Target Organization",
) -> str:
    """
    Generate full incident report PDF.
    Returns path to generated file.
    """
    if not REPORTLAB_OK:
        raise RuntimeError("reportlab not installed. pip install reportlab")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="AutoShield Incident Report",
        author="AutoShield AI",
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Styles ──────────────────────────────────────────────────────────────
    def style(name, **kwargs):
        return ParagraphStyle(name, parent=styles["Normal"], **kwargs)

    S_TITLE = style(
        "title",
        fontSize=24,
        textColor=C_WHITE,
        fontName="Helvetica-Bold",
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    S_SUBTITLE = style(
        "subtitle", fontSize=11, textColor=C_MUTED, alignment=TA_CENTER, spaceAfter=20
    )
    S_H1 = style(
        "h1",
        fontSize=14,
        textColor=C_WHITE,
        fontName="Helvetica-Bold",
        spaceBefore=16,
        spaceAfter=8,
    )
    S_H2 = style(
        "h2",
        fontSize=11,
        textColor=C_BLUE,
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=6,
    )
    S_BODY = style("body", fontSize=9, textColor=C_TEXT, leading=14, spaceAfter=6)
    S_MUTED = style("muted", fontSize=8, textColor=C_MUTED, leading=12)
    S_CODE = style(
        "code",
        fontSize=8,
        textColor=C_GREEN,
        fontName="Courier",
        backColor=C_SURFACE,
        leftIndent=6,
        spaceAfter=4,
    )

    # ── Cover page ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("🛡️ AutoShield AI", S_TITLE))
    story.append(Paragraph("Security Incident Report", S_SUBTITLE))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 0.5 * cm))

    now = datetime.now()
    meta = [
        ["Organization", org_name],
        ["Report Generated", now.strftime("%Y-%m-%d %H:%M:%S")],
        ["Report Period", f"Session — {now.strftime('%Y-%m-%d')}"],
        ["Classification", "CONFIDENTIAL — Internal Use Only"],
        ["System", "AutoShield AI v1.0 (Hackathon Edition)"],
    ]
    meta_table = Table(meta, colWidths=[5 * cm, 10 * cm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), C_SURFACE),
                ("TEXTCOLOR", (0, 0), (0, -1), C_MUTED),
                ("TEXTCOLOR", (1, 0), (1, -1), C_TEXT),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG, C_SURFACE]),
                ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)
    story.append(PageBreak())

    # ── Executive Summary ───────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", S_H1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))

    total = len(attack_events)
    blocked = len([e for e in attack_events if e.get("action") == "BLOCKED"])
    critical = len([e for e in attack_events if e.get("severity") == "CRITICAL"])
    atypes = Counter(e.get("attack_type", "?") for e in attack_events)
    top_type = atypes.most_common(1)[0][0] if atypes else "N/A"
    unique_ips = len({e.get("src_ip") for e in attack_events})

    summary_text = (
        (
            f"AutoShield AI detected and responded to <b>{total} web attacks</b> during this session. "
            f"<b>{blocked} attacks ({int(blocked / total * 100) if total else 0}%)</b> were automatically blocked. "
            f"<b>{critical} CRITICAL severity attacks</b> were identified, predominantly of type <b>{top_type}</b>. "
            f"Attacks originated from <b>{unique_ips} unique IP addresses</b>. "
            f"<b>{len(blocked_ips)} IP addresses</b> are currently blacklisted via iptables rules."
        )
        if total
        else ("No attacks detected in this session. All systems nominal.")
    )
    story.append(Paragraph(summary_text, S_BODY))
    story.append(Spacer(1, 0.5 * cm))

    # Summary stat boxes (as table)
    stats = [
        ["Total Attacks", "Blocked", "CRITICAL", "Unique IPs", "IPs Blocked"],
        [
            str(total),
            str(blocked),
            str(critical),
            str(unique_ips),
            str(len(blocked_ips)),
        ],
    ]
    stat_table = Table(stats, colWidths=[3.2 * cm] * 5)
    stat_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), C_SURFACE),
                ("BACKGROUND", (0, 1), (-1, 1), C_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), C_MUTED),
                ("TEXTCOLOR", (0, 1), (0, 1), C_BLUE),
                ("TEXTCOLOR", (1, 1), (1, 1), C_GREEN),
                ("TEXTCOLOR", (2, 1), (2, 1), C_RED),
                ("TEXTCOLOR", (3, 1), (-1, 1), C_TEXT),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("FONTSIZE", (0, 1), (-1, 1), 18),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_SURFACE, C_BG]),
            ]
        )
    )
    story.append(stat_table)
    story.append(Spacer(1, 0.8 * cm))

    # Attack type breakdown
    if atypes:
        story.append(Paragraph("Attack Type Distribution", S_H2))
        breakdown_data = [["Attack Type", "Count", "% of Total", "Severity"]]
        type_severity = defaultdict(list)
        for e in attack_events:
            type_severity[e.get("attack_type", "?")].append(e.get("severity", "?"))

        for atype, count in atypes.most_common():
            pct = f"{count / total * 100:.1f}%"
            sevs = type_severity[atype]
            worst = (
                "CRITICAL"
                if "CRITICAL" in sevs
                else "HIGH"
                if "HIGH" in sevs
                else "MEDIUM"
            )
            breakdown_data.append([atype, str(count), pct, worst])

        bt = Table(breakdown_data, colWidths=[4 * cm, 3 * cm, 3 * cm, 4 * cm])
        bt.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), C_SURFACE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), C_MUTED),
                    ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_SURFACE]),
                    ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(bt)

    story.append(PageBreak())

    # ── Attack Log ──────────────────────────────────────────────────────────
    story.append(Paragraph("2. Detailed Attack Log", S_H1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))

    if attack_events:
        log_data = [
            ["#", "Timestamp", "Source IP", "Type", "Severity", "Action", "Conf."]
        ]
        for i, ev in enumerate(attack_events[-50:], 1):  # max 50 rows
            ts = (
                ev.get("timestamp", "")[-19:-3]
                if len(ev.get("timestamp", "")) > 10
                else ev.get("timestamp", "")
            )
            sev = ev.get("severity", "?")
            row = [
                str(i),
                ts,
                ev.get("src_ip", "-"),
                ev.get("attack_type", "-"),
                sev,
                ev.get("action", "PENDING"),
                f"{ev.get('confidence', 0)}%",
            ]
            log_data.append(row)

        log_table = Table(
            log_data,
            colWidths=[
                0.8 * cm,
                3.2 * cm,
                3 * cm,
                1.8 * cm,
                2.2 * cm,
                2.5 * cm,
                1.5 * cm,
            ],
        )
        log_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), C_SURFACE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), C_MUTED),
                    ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_SURFACE]),
                    ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(log_table)
    else:
        story.append(Paragraph("No attacks recorded in this session.", S_MUTED))

    story.append(PageBreak())

    # ── Blocked IPs ─────────────────────────────────────────────────────────
    story.append(Paragraph("3. Blocked IP Addresses", S_H1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))

    if blocked_ips:
        ip_data = [
            [
                "IP Address",
                "Attack Type",
                "Severity",
                "Blocked At",
                "Expires At",
                "Method",
            ]
        ]
        for b in blocked_ips:
            ip_data.append(
                [
                    b.get("ip", "-"),
                    b.get("attack_type", "-"),
                    b.get("severity", "-"),
                    b.get("blocked_at", "")[-19:-3]
                    if len(b.get("blocked_at", "")) > 10
                    else "",
                    b.get("expires_at", "")[-19:-3]
                    if len(b.get("expires_at", "")) > 10
                    else "",
                    b.get("method", "in-memory"),
                ]
            )
        ip_table = Table(
            ip_data, colWidths=[3.5 * cm, 2.5 * cm, 2 * cm, 3 * cm, 3 * cm, 2 * cm]
        )
        ip_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), C_SURFACE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), C_MUTED),
                    ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_BG, C_SURFACE]),
                    ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(ip_table)
    else:
        story.append(Paragraph("No IPs currently blocked.", S_MUTED))

    story.append(Spacer(1, 0.8 * cm))

    # ── Recommendations ─────────────────────────────────────────────────────
    story.append(Paragraph("4. Recommendations", S_H1))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))

    RECS = {
        "SQLi": (
            "SQL Injection Mitigation",
            "Use parameterized queries / prepared statements exclusively. "
            "Deploy an ORM with built-in escaping. "
            "Implement input validation whitelist. "
            "Enable database activity monitoring.",
        ),
        "XSS": (
            "Cross-Site Scripting Mitigation",
            "Encode all user-supplied output using context-aware encoding. "
            "Implement Content Security Policy (CSP) headers. "
            "Use HttpOnly and Secure cookie flags. "
            "Deploy a WAF with XSS ruleset.",
        ),
        "LFI": (
            "Local File Inclusion Mitigation",
            "Restrict file access to an allowed directory whitelist. "
            "Never pass user input directly to file system operations. "
            "Disable PHP wrappers (php://filter, data://) in php.ini. "
            "Run application with least-privilege OS user.",
        ),
        "CMDi": (
            "Command Injection Mitigation",
            "Avoid shell execution for user-controlled input entirely. "
            "Use library functions instead of OS commands where possible. "
            "Sanitize and whitelist all command arguments. "
            "Containerize application to limit blast radius.",
        ),
    }

    detected_types = set(e.get("attack_type") for e in attack_events)
    if not detected_types:
        detected_types = set(RECS.keys())

    for atype in ["SQLi", "XSS", "LFI", "CMDi"]:
        if atype in detected_types:
            title, rec_text = RECS[atype]
            story.append(
                Paragraph(
                    f"4.{['SQLi', 'XSS', 'LFI', 'CMDi'].index(atype) + 1} {title}", S_H2
                )
            )
            story.append(Paragraph(rec_text, S_BODY))

    story.append(Spacer(1, 0.5 * cm))

    # ── Footer note ─────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Generated by AutoShield AI | Powered by Scapy + Scikit-learn + NVD CVE API | "
            "CERT-In Advisory Integration | This report is auto-generated and should be reviewed by a qualified security professional.",
            S_MUTED,
        )
    )

    # ── Build PDF ────────────────────────────────────────────────────────────
    doc.build(story)
    log.info(f"Report saved: {output_path}")
    return output_path


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not REPORTLAB_OK:
        print("Install reportlab first: pip install reportlab")
        exit(1)

    from datetime import datetime, timedelta

    demo_events = [
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "192.168.1.10",
            "attack_type": "SQLi",
            "severity": "CRITICAL",
            "action": "BLOCKED",
            "confidence": 75,
            "cve_hints": ["CVE-2023-23752"],
        },
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "10.0.0.22",
            "attack_type": "XSS",
            "severity": "HIGH",
            "action": "BLOCKED",
            "confidence": 50,
            "cve_hints": ["CVE-2023-32315"],
        },
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "172.16.0.5",
            "attack_type": "LFI",
            "severity": "CRITICAL",
            "action": "BLOCKED",
            "confidence": 100,
            "cve_hints": ["CVE-2023-29489"],
        },
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "10.0.0.99",
            "attack_type": "CMDi",
            "severity": "CRITICAL",
            "action": "BLOCKED",
            "confidence": 75,
            "cve_hints": ["CVE-2023-46604"],
        },
    ]
    demo_blocked = [
        {
            "ip": "192.168.1.10",
            "attack_type": "SQLi",
            "severity": "CRITICAL",
            "blocked_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=1)).isoformat(),
            "method": "in-memory",
        },
    ]

    path = generate_report(
        demo_events, demo_blocked, "/tmp/test_report.pdf", "Demo Corp"
    )
    print(f"✅ Report generated: {path}")
