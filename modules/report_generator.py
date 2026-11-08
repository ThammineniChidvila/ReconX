"""PDF report generation with reportlab. Only collected data is included."""
import os
from pathlib import Path
import tempfile
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import config
from modules.observations import build_observations

NAVY, BLUE, GREY = colors.HexColor("#0f1b33"), colors.HexColor("#2b6bff"), colors.HexColor("#5b6b88")
NA = "Not available"
_ss = getSampleStyleSheet()
BODY = ParagraphStyle("b", parent=_ss["BodyText"], fontSize=8.5, leading=11)
H1 = ParagraphStyle("h1", parent=_ss["Title"], fontSize=24, textColor=NAVY, alignment=0, spaceAfter=2)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=12.5, textColor=BLUE, spaceBefore=14, spaceAfter=5)
SUB = ParagraphStyle("s", parent=BODY, textColor=GREY)


def _p(text, style=BODY):
    return Paragraph(escape(str(text)) if text not in (None, "") else NA, style)


def _table(rows, widths, header=True):
    data = [[c if isinstance(c, Paragraph) else _p(c) for c in row] for row in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3e6")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f6fc")])]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(style))
    return t


def _hdr(*cells):
    return [Paragraph(f"<font color='white'><b>{escape(c)}</b></font>", BODY) for c in cells]


def _kv(pairs):
    return _table([[k, v] for k, v in pairs], [45 * mm, 125 * mm], header=False)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(20 * mm, 10 * mm, "ReconX - passive intelligence report. Generated from collected data only.")
    canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _section_note(data):
    return [_p(f"Status: {data.get('status', 'not run')}. {data.get('message', '')}".strip(), SUB)]


def build_story(scan, port_scan=None):
    r = scan["results"] if scan else {}
    domain = (scan or port_scan)["domain"]
    story = [Paragraph("ReconX", H1), _p("Unified Cybersecurity Reconnaissance Report", SUB), Spacer(1, 6),
             _kv([("Target domain", domain), ("Scan date (UTC)", (scan or port_scan)["started_at"]),
                  ("Scan status", (scan or port_scan)["status"]),
                  ("Report sections", "Passive intelligence" + (" + authorised port assessment" if port_scan else ""))])]

    obs = build_observations(r, port_scan["results"] if port_scan else None) if scan else \
        build_observations({}, port_scan["results"])
    story += [Paragraph("Important security observations", H2)]
    story += [_table([_hdr("Severity", "Observation")] + [[o["severity"].upper(), o["text"]] for o in obs], [25 * mm, 145 * mm])] if obs \
        else [_p("No observations could be derived from the collected data.")]

    if scan:
        dns = r.get("dns", {})
        story.append(Paragraph("DNS findings", H2))
        story += _section_note(dns) if dns.get("status") != "ok" else []
        if dns.get("records"):
            story.append(_table([_hdr("Type", "Value", "Status")] + [[x["type"], x["value"], x["status"]] for x in dns["records"]], [20 * mm, 115 * mm, 35 * mm]))
        rd = r.get("rdap", {})
        story.append(Paragraph("RDAP / registration findings", H2))
        if rd.get("status") == "ok":
            story.append(_kv([("Registrar", rd.get("registrar")), ("Registered", rd.get("registered")), ("Expires", rd.get("expires")),
                              ("Last updated", rd.get("updated")), ("Domain status", ", ".join(rd.get("domain_status", []))),
                              ("Name servers", ", ".join(rd.get("nameservers", [])))]))
        else:
            story += _section_note(rd)
        sl = r.get("ssl", {})
        story.append(Paragraph("SSL / TLS findings", H2))
        if sl.get("status") == "ok":
            story.append(_kv([("Issuer", sl.get("issuer")), ("Subject", sl.get("subject")), ("Valid from", sl.get("valid_from")),
                              ("Valid until", sl.get("valid_until")), ("Days remaining", sl.get("days_remaining")),
                              ("Validity", sl.get("validity_status")), ("Hostname verified", {True: "Yes", False: "No"}.get(sl.get("hostname_verified"), NA)),
                              ("Protocol", sl.get("protocol")), ("Verification error", sl.get("verification_error"))]))
        else:
            story += _section_note(sl)
        sd = r.get("subdomains", {})
        story.append(Paragraph("Subdomain findings", H2))
        story.append(_p(f"Source: {sd.get('source', NA)}. Unique subdomains: {sd.get('count', 0)}. Status: {sd.get('status', 'not run')}.", SUB))
        subs = sd.get("subdomains", [])
        if subs:
            shown = subs[:150]
            story.append(_p(", ".join(shown) + (f" ... and {len(subs) - 150} more" if len(subs) > 150 else "")))
        te = r.get("technology", {})
        story.append(Paragraph("Technology findings", H2))
        if te.get("status") == "ok":
            story.append(_kv([("HTTP status", te.get("http_status")), ("HTTPS available", "Yes" if te.get("https_available") else "No"),
                              ("Final URL", te.get("final_url")), ("Server", te.get("server")), ("Page title", te.get("title"))]))
            story.append(Spacer(1, 4))
            story.append(_table([_hdr("Security header", "Present", "Value")] + [[h["header"], "Yes" if h["present"] else "No", h["value"]] for h in te.get("security_headers", [])], [50 * mm, 20 * mm, 100 * mm]))
            if te.get("technologies"):
                story.append(Spacer(1, 4))
                story.append(_table([_hdr("Technology", "Category", "Evidence")] + [[t["name"], t["category"], t["evidence"]] for t in te["technologies"]], [45 * mm, 35 * mm, 90 * mm]))
        else:
            story += _section_note(te) + [_p("; ".join(te.get("notes", [])), SUB)]

    story.append(Paragraph("Authorised port assessment", H2))
    if port_scan and port_scan["results"].get("status") == "ok":
        pr = port_scan["results"]
        story.append(_p(f"Ownership verified via DNS TXT. Target IP {pr['target_ip']}. Duration {pr['duration_seconds']} s.", SUB))
        story.append(_table([_hdr("Port", "Service", "State")] + [[x["port"], x["service"], x["state"]] for x in pr["ports"]], [30 * mm, 70 * mm, 70 * mm]))
    else:
        story.append(_p("No authorised port assessment was performed for this domain.", SUB))
    return story


def generate_report(scan, port_scan=None, out_dir=None):
    base = scan or port_scan

    if out_dir is not None:
        output_dir = Path(out_dir)
    elif os.getenv("VERCEL"):
        output_dir = Path(tempfile.gettempdir()) / "reconx-reports"
    else:
        output_dir = config.REPORTS_DIR

    output_dir.mkdir(parents=True, exist_ok=True)

    path = output_dir / f"ReconX_{base['domain']}_{base['id']}.pdf"

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"ReconX report - {base['domain']}",
        author="ReconX"
    )

    doc.build(
        build_story(scan, port_scan),
        onFirstPage=_footer,
        onLaterPages=_footer
    )
    return path