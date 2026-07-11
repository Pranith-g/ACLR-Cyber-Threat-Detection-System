import io
import json
import zipfile

from utils.file_threat_detector import analyze_file


def make_docx(xml_body: str, include_macro=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("word/document.xml", xml_body)
        archive.writestr("word/_rels/document.xml.rels", "<Relationships></Relationships>")
        if include_macro:
            archive.writestr("word/vbaProject.bin", b"fake-macro")
    return buffer.getvalue()


TEST_CASES = [
    ("safe.exe", b"MZ" + (b"\x00" * 700000)),
    ("malicious.exe", b"MZUPX" + b"eicar malware payload powershell -enc " + (b"\x90" * 1024)),
    ("safe.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"),
    ("malicious.pdf", b"%PDF-1.7\n1 0 obj\n<< /OpenAction 2 0 R /JS (app.alert('x')) /EmbeddedFile true >>\nendobj\n%%EOF"),
    ("safe.docx", make_docx("<w:document><w:p>Hello report</w:p></w:document>")),
    ("malicious.docx", make_docx("<w:document><w:instrText>DDEAUTO powershell</w:instrText></w:document>", include_macro=True)),
    ("safe.json", json.dumps({"name": "inventory", "items": [1, 2, 3]}).encode("utf-8")),
    ("malicious.json", json.dumps({
        "command": "powershell -enc ZQBjAGgAbwA=",
        "download_url": "http://bad.example/payload",
        "payload": "SGVsbG8=" * 12,
    }).encode("utf-8")),
]


def main():
    print("Running detector validation...\n")
    for file_name, content in TEST_CASES:
        result = analyze_file(file_name, content)
        print(
            f"{file_name:<18} -> type={result['file_type']:<4} "
            f"label={result['label']:<10} risk={result['risk']:<6} "
            f"confidence={result['confidence']}"
        )
        if result["reasons"]:
            print("  reasons:", "; ".join(result["reasons"][:3]))
    print("\nValidation finished.")


if __name__ == "__main__":
    main()
