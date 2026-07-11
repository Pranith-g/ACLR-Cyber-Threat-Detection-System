import io
import json
import math
import re
import zipfile
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd
import pefile


SUPPORTED_EXTENSIONS = ("exe", "pdf", "docx", "json")
MODEL_PATH = Path("models") / "file_threat_detector.pkl"
DATASET_PATH = Path("dataset") / "file_threat_training_dataset.csv"

FEATURE_COLUMNS = [
    "file_type_code",
    "size_bytes",
    "entropy",
    "printable_ratio",
    "null_ratio",
    "control_ratio",
    "suspicious_keyword_hits",
    "script_keyword_hits",
    "url_count",
    "base64_blob_count",
    "has_mz",
    "has_pdf",
    "has_zip",
    "is_json_valid",
    "pe_section_count",
    "pdf_js_count",
    "pdf_openaction_count",
    "pdf_embedded_count",
    "doc_has_macro",
    "doc_has_external_link",
    "doc_has_embedding",
    "json_command_fields",
    "json_suspicious_values",
    "text_length",
]

TYPE_CODE_MAP = {
    "exe": 0,
    "pdf": 1,
    "docx": 2,
    "json": 3,
}

TEXT_SUSPICIOUS_PATTERNS = [
    "eicar",
    "malware",
    "virus",
    "trojan",
    "worm",
    "ransomware",
    "spyware",
    "keylogger",
    "payload",
    "shellcode",
    "backdoor",
    "botnet",
    "phishing",
    "encrypt all files",
    "steal password",
    "cmd.exe",
    "powershell -enc",
    "powershell.exe",
    "invoke-webrequest",
    "downloadstring",
    "frombase64string",
    "regsvr32",
    "mshta",
    "rundll32",
    "cscript",
    "wscript",
]

SCRIPT_PATTERNS = [
    "javascript",
    "powershell",
    "vbscript",
    "cmd /c",
    "bash -c",
    "wscript.shell",
    "openaction",
    "launch",
    "ddeauto",
]

BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _entropy(content: bytes) -> float:
    if not content:
        return 0.0
    counts = Counter(content)
    return -sum((count / len(content)) * math.log2(count / len(content)) for count in counts.values())


def _decode_text(content: bytes) -> str:
    return content.decode("utf-8", errors="ignore") or content.decode("latin-1", errors="ignore")


def _safe_ratio(numerator: float, denominator: float) -> float:
    if not denominator:
        return 0.0
    return float(numerator) / float(denominator)


def _count_pattern_hits(text: str, patterns) -> int:
    lowered = text.lower()
    return sum(1 for pattern in patterns if pattern in lowered)


def _detect_extension(filename: str) -> str:
    suffix = Path(filename or "").suffix.lower().lstrip(".")
    return suffix if suffix in SUPPORTED_EXTENSIONS else "unknown"


def _extract_docx_signals(content: bytes) -> dict:
    signals = {
        "valid_docx": False,
        "doc_has_macro": 0,
        "doc_has_external_link": 0,
        "doc_has_embedding": 0,
        "text": "",
        "notes": [],
    }

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
            signals["valid_docx"] = "[Content_Types].xml" in names and "word/document.xml" in names

            if "word/vbaProject.bin" in names:
                signals["doc_has_macro"] = 1
                signals["notes"].append("Embedded VBA macro project found")

            if any(name.startswith("word/embeddings/") for name in names):
                signals["doc_has_embedding"] = 1
                signals["notes"].append("Embedded document/object found")

            rels_content = ""
            document_content = ""
            for name in names:
                if name.endswith(".rels"):
                    rels_content += archive.read(name).decode("utf-8", errors="ignore")
                if name.endswith(".xml") and name.startswith("word/"):
                    document_content += archive.read(name).decode("utf-8", errors="ignore")

            if 'TargetMode="External"' in rels_content or "http://" in rels_content.lower() or "https://" in rels_content.lower():
                signals["doc_has_external_link"] = 1
                signals["notes"].append("External relationship found inside DOCX package")

            if "DDEAUTO" in document_content.upper():
                signals["doc_has_external_link"] = 1
                signals["notes"].append("DDEAUTO field found")

            if "<o:OLEObject" in document_content or "oleObject" in document_content:
                signals["doc_has_embedding"] = 1
                signals["notes"].append("OLE object marker found")

            signals["text"] = f"{rels_content}\n{document_content}"
    except Exception:
        pass

    return signals


def _extract_json_signals(content: bytes) -> dict:
    text = _decode_text(content)
    lowered = text.lower()
    signals = {
        "is_json_valid": 0,
        "json_command_fields": 0,
        "json_suspicious_values": 0,
        "text": text,
        "notes": [],
    }

    suspicious_keys = {
        "command",
        "cmd",
        "script",
        "powershell",
        "payload",
        "downloadurl",
        "download_url",
        "encodedcommand",
        "exec",
        "shell",
    }

    try:
        parsed = json.loads(text)
        signals["is_json_valid"] = 1

        def walk(node):
            command_fields = 0
            suspicious_values = 0
            if isinstance(node, dict):
                for key, value in node.items():
                    if str(key).lower() in suspicious_keys:
                        command_fields += 1
                    c_hits, s_hits = walk(value)
                    command_fields += c_hits
                    suspicious_values += s_hits
            elif isinstance(node, list):
                for item in node:
                    c_hits, s_hits = walk(item)
                    command_fields += c_hits
                    suspicious_values += s_hits
            else:
                raw = str(node).lower()
                if any(pattern in raw for pattern in TEXT_SUSPICIOUS_PATTERNS + SCRIPT_PATTERNS):
                    suspicious_values += 1
                if URL_PATTERN.search(raw) or BASE64_PATTERN.search(raw):
                    suspicious_values += 1
            return command_fields, suspicious_values

        signals["json_command_fields"], signals["json_suspicious_values"] = walk(parsed)
        if signals["json_command_fields"]:
            signals["notes"].append("Command-like JSON fields found")
        if signals["json_suspicious_values"]:
            signals["notes"].append("Suspicious JSON values found")
    except Exception:
        if any(pattern in lowered for pattern in TEXT_SUSPICIOUS_PATTERNS):
            signals["json_suspicious_values"] += 1
            signals["notes"].append("JSON parse failed and suspicious text was found")

    return signals


def _extract_pdf_signals(content: bytes) -> dict:
    text = _decode_text(content)
    lowered = text.lower()
    js_count = lowered.count("/js") + lowered.count("/javascript")
    openaction_count = lowered.count("/openaction")
    embedded_count = lowered.count("/embeddedfile") + lowered.count("/launch") + lowered.count("/richmedia")
    notes = []
    if js_count:
        notes.append("JavaScript marker found in PDF")
    if openaction_count:
        notes.append("OpenAction found in PDF")
    if embedded_count:
        notes.append("Embedded file or launch action found in PDF")
    return {
        "text": text,
        "pdf_js_count": js_count,
        "pdf_openaction_count": openaction_count,
        "pdf_embedded_count": embedded_count,
        "notes": notes,
    }


def _extract_exe_signals(content: bytes) -> dict:
    notes = []
    pe_sections = 0
    try:
        pe = pefile.PE(data=content)
        pe_sections = len(pe.sections)
    except Exception:
        pass

    if b"UPX" in content[:200000]:
        notes.append("Packed signature found (UPX)")
    if pe_sections and pe_sections <= 2:
        notes.append("Very low PE section count")

    return {
        "pe_section_count": pe_sections,
        "notes": notes,
    }


def extract_file_features(file_name: str, content: bytes) -> dict:
    extension = _detect_extension(file_name)
    text = _decode_text(content)
    printable = sum(1 for char in text if char.isprintable())
    control_chars = sum(1 for char in text if ord(char) < 32 and char not in "\r\n\t")
    lowered = text.lower()

    features = {
        "file_type": extension,
        "file_type_code": TYPE_CODE_MAP.get(extension, -1),
        "size_bytes": len(content),
        "entropy": round(_entropy(content), 6),
        "printable_ratio": round(_safe_ratio(printable, max(len(text), 1)), 6),
        "null_ratio": round(_safe_ratio(content.count(0), max(len(content), 1)), 6),
        "control_ratio": round(_safe_ratio(control_chars, max(len(text), 1)), 6),
        "suspicious_keyword_hits": _count_pattern_hits(lowered, TEXT_SUSPICIOUS_PATTERNS),
        "script_keyword_hits": _count_pattern_hits(lowered, SCRIPT_PATTERNS),
        "url_count": len(URL_PATTERN.findall(text)),
        "base64_blob_count": len(BASE64_PATTERN.findall(text)),
        "has_mz": int(content.startswith(b"MZ")),
        "has_pdf": int(content.startswith(b"%PDF")),
        "has_zip": int(content.startswith(b"PK")),
        "is_json_valid": 0,
        "pe_section_count": 0,
        "pdf_js_count": 0,
        "pdf_openaction_count": 0,
        "pdf_embedded_count": 0,
        "doc_has_macro": 0,
        "doc_has_external_link": 0,
        "doc_has_embedding": 0,
        "json_command_fields": 0,
        "json_suspicious_values": 0,
        "text_length": len(text),
    }

    notes = []

    if extension == "exe":
        exe_signals = _extract_exe_signals(content)
        features["pe_section_count"] = exe_signals["pe_section_count"]
        notes.extend(exe_signals["notes"])
    elif extension == "pdf":
        pdf_signals = _extract_pdf_signals(content)
        features["pdf_js_count"] = pdf_signals["pdf_js_count"]
        features["pdf_openaction_count"] = pdf_signals["pdf_openaction_count"]
        features["pdf_embedded_count"] = pdf_signals["pdf_embedded_count"]
        notes.extend(pdf_signals["notes"])
    elif extension == "docx":
        docx_signals = _extract_docx_signals(content)
        features["doc_has_macro"] = docx_signals["doc_has_macro"]
        features["doc_has_external_link"] = docx_signals["doc_has_external_link"]
        features["doc_has_embedding"] = docx_signals["doc_has_embedding"]
        features["script_keyword_hits"] += _count_pattern_hits(docx_signals["text"].lower(), SCRIPT_PATTERNS)
        features["suspicious_keyword_hits"] += _count_pattern_hits(docx_signals["text"].lower(), TEXT_SUSPICIOUS_PATTERNS)
        features["url_count"] += len(URL_PATTERN.findall(docx_signals["text"]))
        notes.extend(docx_signals["notes"])
        if not docx_signals["valid_docx"]:
            notes.append("DOCX container structure is invalid")
    elif extension == "json":
        json_signals = _extract_json_signals(content)
        features["is_json_valid"] = json_signals["is_json_valid"]
        features["json_command_fields"] = json_signals["json_command_fields"]
        features["json_suspicious_values"] = json_signals["json_suspicious_values"]
        notes.extend(json_signals["notes"])

    return {
        "features": features,
        "text": text,
        "notes": notes,
    }


def load_model_bundle():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None


def score_with_heuristics(file_name: str, feature_map: dict, text: str, notes):
    extension = feature_map["file_type"]
    score = 0
    reasons = list(notes)
    lowered = text.lower()

    if "eicar" in lowered:
        return {
            "label": "Malicious",
            "risk": "HIGH",
            "confidence": 99.0,
            "score": 100,
            "reasons": reasons + ["EICAR test string detected"],
        }

    if extension == "exe":
        if not feature_map["has_mz"]:
            score += 4
            reasons.append("EXE extension does not contain a valid MZ header")
        if feature_map["entropy"] >= 7.2:
            score += 3
            reasons.append("High entropy suggests packing or obfuscation")
        if feature_map["pe_section_count"] == 0:
            score += 3
            reasons.append("PE sections could not be read")
        elif feature_map["pe_section_count"] <= 2:
            score += 2
        if feature_map["size_bytes"] < 300 * 1024:
            score += 2
            reasons.append("Very small executable size")
        if feature_map["suspicious_keyword_hits"] >= 2:
            score += 2
            reasons.append("Threat-related strings found in executable text")
    elif extension == "pdf":
        if not feature_map["has_pdf"]:
            score += 4
            reasons.append("PDF extension does not contain a PDF header")
        score += min(4, feature_map["pdf_js_count"] * 2)
        score += min(3, feature_map["pdf_openaction_count"] * 2)
        score += min(4, feature_map["pdf_embedded_count"] * 2)
        if feature_map["pdf_js_count"] and (
            feature_map["pdf_openaction_count"] or feature_map["pdf_embedded_count"]
        ):
            score += 2
            reasons.append("PDF combines JavaScript with an action or embedded payload")
        if feature_map["entropy"] > 7.0:
            score += 1
        if feature_map["suspicious_keyword_hits"] >= 2:
            score += 1
    elif extension == "docx":
        if not feature_map["has_zip"]:
            score += 4
            reasons.append("DOCX extension does not contain a ZIP header")
        if feature_map["doc_has_macro"]:
            score += 4
            reasons.append("DOCX macro content detected")
        if feature_map["doc_has_external_link"]:
            score += 3
        if feature_map["doc_has_embedding"]:
            score += 2
        if feature_map["script_keyword_hits"] >= 2:
            score += 2
            reasons.append("Script-like text found inside DOCX package")
    elif extension == "json":
        if not feature_map["is_json_valid"]:
            score += 2
            reasons.append("JSON file could not be parsed cleanly")
        score += min(4, feature_map["json_command_fields"] * 2)
        score += min(4, feature_map["json_suspicious_values"])
        if feature_map["base64_blob_count"] >= 2:
            score += 2
            reasons.append("Large Base64 blobs found in JSON")
        if feature_map["url_count"] >= 2:
            score += 1
        if feature_map["script_keyword_hits"] >= 2:
            score += 2

    if extension == "unknown":
        reasons.append("Unsupported file extension")
        return {
            "label": "Unsupported",
            "risk": "MEDIUM",
            "confidence": 0.0,
            "score": score,
            "reasons": reasons,
        }

    if score >= 7:
        label = "Malicious"
        risk = "HIGH"
    elif score >= 4:
        label = "Suspicious"
        risk = "MEDIUM"
    else:
        label = "Safe"
        risk = "LOW"

    confidence = min(99.0, 45.0 + (score * 7.5))
    return {
        "label": label,
        "risk": risk,
        "confidence": round(confidence, 2),
        "score": score,
        "reasons": reasons,
    }


def analyze_file(file_name: str, content: bytes):
    extracted = extract_file_features(file_name, content)
    feature_map = extracted["features"]
    heuristic = score_with_heuristics(file_name, feature_map, extracted["text"], extracted["notes"])

    model_bundle = load_model_bundle()
    model_probability = None
    model_prediction = None

    if model_bundle is not None and feature_map["file_type"] in SUPPORTED_EXTENSIONS:
        feature_frame = pd.DataFrame([[feature_map[column] for column in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
        model = model_bundle["model"]
        probability = float(model.predict_proba(feature_frame)[0][1])
        model_probability = round(probability * 100, 2)
        model_prediction = "Malicious" if probability >= 0.5 else "Safe"

        if model_probability >= 90 and heuristic["label"] == "Safe":
            heuristic["label"] = "Suspicious"
            heuristic["risk"] = "MEDIUM"
            heuristic["reasons"].append("Model flagged this file even though heuristic risk was low")
        elif model_probability >= 90 and heuristic["label"] != "Malicious":
            heuristic["label"] = "Malicious"
            heuristic["risk"] = "HIGH"
            heuristic["reasons"].append("Model confidence is very high for malicious behavior")

        heuristic["confidence"] = round(max(heuristic["confidence"], model_probability), 2)

    return {
        "file_type": feature_map["file_type"],
        "features": feature_map,
        "label": heuristic["label"],
        "risk": heuristic["risk"],
        "confidence": heuristic["confidence"],
        "heuristic_score": heuristic["score"],
        "reasons": heuristic["reasons"],
        "model_probability": model_probability,
        "model_prediction": model_prediction,
    }
