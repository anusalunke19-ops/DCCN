"""
generate_pdf_report.py — Converts network_forensics_analyzer_report.md into a professional PDF.
Eliminates all unmapped unicode glyphs (emojis, box drawings) that cause solid squares in PDF viewers.
"""

import os
import re
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable, Preformatted
)
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

MD_PATH = r"C:\Users\Kunshu\.gemini\antigravity\brain\222988d5-32db-400d-8958-adaf7cf31ee8\network_forensics_analyzer_report.md"
PDF_PATH = r"C:\Users\Kunshu\Documents\Sem 5\DCCN\ananya_version\DCCN\Network_Forensics_Analyzer_Report.pdf"
ARTIFACT_PDF_PATH = r"C:\Users\Kunshu\.gemini\antigravity\brain\222988d5-32db-400d-8958-adaf7cf31ee8\Network_Forensics_Analyzer_Report.pdf"

# Register standard Windows TrueType fonts for clean, crisp rendering
pdfmetrics.registerFont(TTFont("Arial", r"C:\Windows\Fonts\arial.ttf"))
pdfmetrics.registerFont(TTFont("Arial-Bold", r"C:\Windows\Fonts\arialbd.ttf"))
pdfmetrics.registerFont(TTFont("Arial-Italic", r"C:\Windows\Fonts\ariali.ttf"))
pdfmetrics.registerFont(TTFont("Consolas", r"C:\Windows\Fonts\consola.ttf"))
pdfmetrics.registerFont(TTFont("Consolas-Bold", r"C:\Windows\Fonts\consolab.ttf"))


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Arial", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (Pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 755, "Network Forensics Analyzer -- Technical & Academic Report")
            self.drawRightString(558, 755, "DCCN Coursework")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.6)
            self.line(54, 747, 558, 747)

        # Footer (All pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "Data Communication & Computer Networks (DCCN) | Python, Scapy & Streamlit")
        self.drawRightString(558, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def sanitize_text(text: str) -> str:
    """Strip or replace all unicode characters that trigger solid squares/tofu in PDF viewers."""
    replacements = [
        # Emojis & Pictographs
        ('🔬', ''), ('📊', ''), ('📡', ''), ('🔍', ''), ('🔗', ''), ('📈', ''),
        ('⚖️', ''), ('⚖', ''), ('🎓', ''), ('🧪', ''), ('📂', ''), ('💾', ''),
        ('⬅️', '<-'), ('⬅', '<-'), ('➡️', '->'), ('➡', '->'), ('🚀', ''),
        ('🤝', ''), ('📁', ''), ('📘', ''), ('🦈', ''), ('📦', ''), ('⚡', ''),
        ('▶', '>'), ('✓', '[PASS]'), ('✕', '[X]'), ('⚠', '[!]'),
        ('●', '*'), ('○', 'o'),
        # Arrows & Directions
        ('➔', '->'), ('→', '->'), ('←', '<-'), ('⇄', '<->'), ('↔', '<->'),
        # Mathematical / Punctuation
        ('±', '+/-'), ('—', '--'), ('–', '-'),
        # Box Drawing / Tree Characters
        ('├──', '|-- '), ('└──', '\\-- '), ('──', '--'), ('│', '|'),
        ('├', '|'), ('└', '\\'), ('─', '-')
    ]
    for src, dst in replacements:
        text = text.replace(src, dst)
    return text


def format_inline_markdown(text: str) -> str:
    """Convert common inline markdown tags to ReportLab XML tags safely."""
    text = sanitize_text(text)

    # Convert KaTeX / Math indicators to clean typography
    text = text.replace(r"\longrightarrow", " -> ")
    text = text.replace(r"\xrightarrow", " -> ")
    text = text.replace(r"\quad", " ")
    text = text.replace(r"\pm", "+/-")
    text = text.replace(r"\leftrightarrow", " <-> ")
    text = re.sub(r"\$\\text\{([^\}]+)\}\$", r"<b>\1</b>", text)
    text = re.sub(r"\$([^\$]+)\$", r"<i>\1</i>", text)
    
    # Subscripts
    text = text.replace("ISN_c", "ISN<sub>c</sub>")
    text = text.replace("ISN_s", "ISN<sub>s</sub>")
    text = text.replace("Sock_A", "Sock<sub>A</sub>")
    text = text.replace("Sock_B", "Sock<sub>B</sub>")

    # Links: [label](url) -> label
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"<b>\1</b>", text)

    # Bold + Italic: ***text***
    text = re.sub(r"\*\*\*([^*]+)\*\*\*", r"<b><i>\1</i></b>", text)
    # Bold: **text**
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    # Italic: *text*
    text = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", text)
    # Code span: `text`
    text = re.sub(r"`([^`]+)`", r'<font face="Consolas" color="#0F766E"><b>\1</b></font>', text)

    # Escape raw ampersands not part of XML entities
    text = re.sub(r"&(?!(amp|lt|gt|quot|apos);)", "&amp;", text)

    return text


def build_pdf():
    with open(MD_PATH, "r", encoding="utf-8") as f:
        md_content = f.read()

    doc = SimpleDocTemplate(
        PDF_PATH,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    base_styles = getSampleStyleSheet()

    styles = {
        "Title": ParagraphStyle(
            "DocTitle",
            parent=base_styles["Title"],
            fontName="Arial-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F766E"),
            alignment=0,
            spaceAfter=6
        ),
        "Subtitle": ParagraphStyle(
            "DocSubtitle",
            parent=base_styles["Normal"],
            fontName="Arial",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=14
        ),
        "H1": ParagraphStyle(
            "Heading1",
            parent=base_styles["Heading1"],
            fontName="Arial-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#0F766E"),
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        ),
        "H2": ParagraphStyle(
            "Heading2",
            parent=base_styles["Heading2"],
            fontName="Arial-Bold",
            fontSize=11.5,
            leading=15.5,
            textColor=colors.HexColor("#159A91"),
            spaceBefore=11,
            spaceAfter=5,
            keepWithNext=True
        ),
        "H3": ParagraphStyle(
            "Heading3",
            parent=base_styles["Heading3"],
            fontName="Arial-Bold",
            fontSize=10,
            leading=13.5,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=9,
            spaceAfter=4,
            keepWithNext=True
        ),
        "Body": ParagraphStyle(
            "BodyText",
            parent=base_styles["Normal"],
            fontName="Arial",
            fontSize=9.2,
            leading=13.5,
            textColor=colors.HexColor("#263238"),
            spaceAfter=5
        ),
        "Bullet": ParagraphStyle(
            "BulletText",
            parent=base_styles["Normal"],
            fontName="Arial",
            fontSize=9.2,
            leading=13.5,
            textColor=colors.HexColor("#263238"),
            leftIndent=15,
            firstLineIndent=-10,
            spaceAfter=3.5
        ),
        "Callout": ParagraphStyle(
            "CalloutText",
            parent=base_styles["Normal"],
            fontName="Arial",
            fontSize=8.8,
            leading=12.5,
            textColor=colors.HexColor("#0F766E"),
            spaceBefore=3,
            spaceAfter=3
        ),
        "CodeBlock": ParagraphStyle(
            "CodeBlockText",
            parent=base_styles["Code"],
            fontName="Consolas",
            fontSize=7.8,
            leading=10.5,
            textColor=colors.HexColor("#1E293B"),
        ),
        "TableCell": ParagraphStyle(
            "TableCellText",
            parent=base_styles["Normal"],
            fontName="Arial",
            fontSize=8.2,
            leading=11,
            textColor=colors.HexColor("#263238"),
        ),
        "TableHeader": ParagraphStyle(
            "TableHeaderText",
            parent=base_styles["Normal"],
            fontName="Arial-Bold",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.white,
        ),
    }

    story = []

    # Title Banner Block
    story.append(Paragraph("Network Forensics Analyzer", styles["Title"]))
    story.append(Paragraph("Comprehensive Technical Architecture, User Manual, &amp; DCCN Concepts", styles["Subtitle"]))
    
    meta_html = (
        "<b>Target Coursework:</b> Data Communication &amp; Computer Networks (DCCN) &nbsp;|&nbsp; "
        "<b>Environment:</b> Windows 11<br/>"
        "<b>Technology Stack:</b> Python 3.14, Scapy, Streamlit, Plotly, Pandas, Pytest &nbsp;|&nbsp; "
        "<b>Verification:</b> 100% Operational (55/55 Passing Tests)"
    )
    meta_table = Table([[Paragraph(meta_html, styles["TableCell"])]], colWidths=[504])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ('LINELEFT', (0, 0), (0, -1), 3.5, colors.HexColor("#159A91")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # Parse lines from Markdown
    lines = md_content.splitlines()
    in_code_block = False
    code_block_lines = []
    code_block_lang = ""
    in_table = False
    table_lines = []
    in_callout = False
    callout_lines = []

    def flush_code_block():
        nonlocal in_code_block, code_block_lines, code_block_lang
        if code_block_lines:
            # If it was a Mermaid diagram, render it as an Architecture Table instead of raw syntax
            if code_block_lang == "mermaid" or any("flowchart" in l for l in code_block_lines):
                arch_rows = [
                    [Paragraph("<b>Pipeline Stage</b>", styles["TableHeader"]), Paragraph("<b>Sub-Components &amp; Responsibilities</b>", styles["TableHeader"])],
                    [Paragraph("<b>1. Ingestion Engine</b>", styles["TableCell"]), Paragraph("Live NIC sniffing via Npcap &amp; thread-safe bounded queue; Offline PCAP/PCAPNG ingestion; Built-in 7-Protocol synthetic suite.", styles["TableCell"])],
                    [Paragraph("<b>2. Core Processing</b>", styles["TableCell"]), Paragraph("<b>core.packet_parser:</b> Layer-by-layer header field dissection.<br/><b>core.flow_analyzer:</b> Bidirectional 5-tuple socket grouping &amp; state machine.<br/><b>core.protocol_analyzer:</b> Traffic volume &amp; behavioral analytics.<br/><b>core.explain:</b> Plain-English takeaways &amp; TTL hop deduction.", styles["TableCell"])],
                    [Paragraph("<b>3. State Management</b>", styles["TableCell"]), Paragraph("<b>st.session_state:</b> Single unidirectional state cache preserving packets, active selections, and filters across reruns.<br/><b>config/user_progress.json:</b> Academy progress and quiz scores store.", styles["TableCell"])],
                    [Paragraph("<b>4. Presentation Layer</b>", styles["TableCell"]), Paragraph("7 Dedicated Workspaces: Overview, Live Capture, Packet Inspector, TCP Connections, Network Analytics, Capture Comparison, and Guided Labs.", styles["TableCell"])],
                ]
                t = Table(arch_rows, colWidths=[130, 374])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#159A91")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
            else:
                # Regular code block: sanitize all lines
                sanitized_lines = [sanitize_text(l) for l in code_block_lines]
                code_text = "\n".join(sanitized_lines)
                p = Preformatted(code_text, styles["CodeBlock"])
                t = Table([[p]], colWidths=[504])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor("#E2E8F0")),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
        in_code_block = False
        code_block_lines = []
        code_block_lang = ""

    def flush_table():
        nonlocal in_table, table_lines
        if table_lines:
            parsed_rows = []
            for r_idx, t_line in enumerate(table_lines):
                if re.match(r"^\|(\s*:?-+:?\s*\|)+$", t_line.strip()):
                    continue
                cols = [c.strip() for c in t_line.strip().strip("|").split("|")]
                if not cols:
                    continue
                row_elements = []
                for c in cols:
                    style_to_use = styles["TableHeader"] if r_idx == 0 else styles["TableCell"]
                    row_elements.append(Paragraph(format_inline_markdown(c), style_to_use))
                parsed_rows.append(row_elements)

            if parsed_rows:
                num_cols = max(len(r) for r in parsed_rows)
                for r in parsed_rows:
                    while len(r) < num_cols:
                        r.append(Paragraph("", styles["TableCell"]))
                
                if num_cols == 2:
                    col_widths = [130, 374]
                elif num_cols == 3:
                    col_widths = [100, 160, 244]
                elif num_cols == 4:
                    col_widths = [90, 110, 150, 154]
                else:
                    col_widths = [504 / num_cols] * num_cols

                t = Table(parsed_rows, colWidths=col_widths, repeatRows=1)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#159A91")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ]))
                story.append(t)
                story.append(Spacer(1, 8))
        in_table = False
        table_lines = []

    def flush_callout():
        nonlocal in_callout, callout_lines
        if callout_lines:
            callout_text = " ".join(callout_lines)
            p = Paragraph(format_inline_markdown(callout_text), styles["Callout"])
            t = Table([[p]], colWidths=[504])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F0FDFA")),
                ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor("#99F6E4")),
                ('LINELEFT', (0, 0), (0, -1), 3.5, colors.HexColor("#159A91")),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(t)
            story.append(Spacer(1, 8))
        in_callout = False
        callout_lines = []

    skip_header = True

    for line in lines:
        raw_line = line.rstrip()

        # Skip initial H1 and metadata since custom header is rendered
        if skip_header:
            if raw_line.startswith("## 1. Executive Summary"):
                skip_header = False
            else:
                continue

        # Code block handling
        if raw_line.startswith("```"):
            if in_code_block:
                flush_code_block()
            else:
                if in_table: flush_table()
                if in_callout: flush_callout()
                in_code_block = True
                code_block_lang = raw_line[3:].strip().lower()
                code_block_lines = []
            continue

        if in_code_block:
            code_block_lines.append(raw_line)
            continue

        # Table handling
        if raw_line.startswith("|") and raw_line.endswith("|"):
            if not in_table:
                if in_callout: flush_callout()
                in_table = True
                table_lines = []
            table_lines.append(raw_line)
            continue
        elif in_table:
            flush_table()

        # Callout handling
        if raw_line.startswith(">"):
            if not in_callout:
                in_callout = True
                callout_lines = []
            cleaned = re.sub(r"^>\s*(\[!TIP\]|\[!NOTE\]|\[!IMPORTANT\])?\s*", "", raw_line)
            if cleaned:
                callout_lines.append(cleaned)
            continue
        elif in_callout:
            flush_callout()

        # Blank line
        if not raw_line.strip():
            continue

        # Headings
        if raw_line.startswith("## "):
            h_text = raw_line[3:].strip()
            story.append(Spacer(1, 6))
            story.append(Paragraph(format_inline_markdown(h_text), styles["H1"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#159A91"), spaceAfter=8, spaceBefore=2))
            continue
        elif raw_line.startswith("### "):
            h_text = raw_line[4:].strip()
            story.append(Paragraph(format_inline_markdown(h_text), styles["H2"]))
            continue
        elif raw_line.startswith("#### "):
            h_text = raw_line[5:].strip()
            story.append(Paragraph(format_inline_markdown(h_text), styles["H3"]))
            continue

        # Bullet lines
        if raw_line.strip().startswith(("- ", "* ")):
            item_text = re.sub(r"^\s*[-*]\s+", "", raw_line)
            formatted = "* &nbsp; " + format_inline_markdown(item_text)
            story.append(Paragraph(formatted, styles["Bullet"]))
            continue

        # Numbered list lines
        if re.match(r"^\s*\d+\.\s+", raw_line):
            item_text = re.sub(r"^\s*(\d+)\.\s+", r"\1. &nbsp; ", raw_line)
            story.append(Paragraph(format_inline_markdown(item_text), styles["Bullet"]))
            continue

        # Regular Body Paragraph
        story.append(Paragraph(format_inline_markdown(raw_line), styles["Body"]))

    # Final flushes
    if in_code_block: flush_code_block()
    if in_table: flush_table()
    if in_callout: flush_callout()

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Generated clean PDF successfully at: {PDF_PATH}")

    shutil.copyfile(PDF_PATH, ARTIFACT_PDF_PATH)
    print(f"Copied clean PDF to artifact directory: {ARTIFACT_PDF_PATH}")


if __name__ == "__main__":
    build_pdf()
