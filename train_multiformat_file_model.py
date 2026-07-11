import random
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from utils.file_threat_detector import (
    DATASET_PATH,
    FEATURE_COLUMNS,
    MODEL_PATH,
    TYPE_CODE_MAP,
)


PROJECT_ROOT = Path(__file__).resolve().parent
EXTERNAL_DATASET_DIR = PROJECT_ROOT / "dataset" / "external"


def _base_row(file_type: str, label: int):
    return {
        "file_type": file_type,
        "file_type_code": TYPE_CODE_MAP[file_type],
        "size_bytes": 0,
        "entropy": 0.0,
        "printable_ratio": 0.0,
        "null_ratio": 0.0,
        "control_ratio": 0.0,
        "suspicious_keyword_hits": 0,
        "script_keyword_hits": 0,
        "url_count": 0,
        "base64_blob_count": 0,
        "has_mz": 0,
        "has_pdf": 0,
        "has_zip": 0,
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
        "text_length": 0,
        "label": label,
    }


def build_exe_rows():
    clean = pd.read_csv(EXTERNAL_DATASET_DIR / "Clean-2501_name_size_entropy.csv")
    malware = pd.read_csv(EXTERNAL_DATASET_DIR / "Malware-2722_hash_size_entropy.csv")

    rows = []
    rng = random.Random(42)

    for _, item in clean.iterrows():
        row = _base_row("exe", 0)
        row.update(
            {
                "size_bytes": int(item["filesize"]),
                "entropy": float(item["entropy"]),
                "printable_ratio": round(rng.uniform(0.10, 0.36), 6),
                "null_ratio": round(rng.uniform(0.02, 0.18), 6),
                "control_ratio": round(rng.uniform(0.01, 0.06), 6),
                "has_mz": 1,
                "pe_section_count": rng.randint(4, 8),
                "text_length": rng.randint(1000, 18000),
            }
        )
        rows.append(row)

    for _, item in malware.iterrows():
        row = _base_row("exe", 1)
        row.update(
            {
                "size_bytes": int(item["filesize"]),
                "entropy": float(item["entropy"]),
                "printable_ratio": round(rng.uniform(0.04, 0.24), 6),
                "null_ratio": round(rng.uniform(0.05, 0.25), 6),
                "control_ratio": round(rng.uniform(0.02, 0.12), 6),
                "suspicious_keyword_hits": rng.randint(0, 3),
                "script_keyword_hits": rng.randint(0, 2),
                "base64_blob_count": rng.randint(0, 1),
                "has_mz": 1,
                "pe_section_count": rng.randint(1, 5),
                "text_length": rng.randint(700, 9000),
            }
        )
        rows.append(row)

    return rows


def build_pdf_rows():
    pdf_df = pd.read_csv(EXTERNAL_DATASET_DIR / "PDFMalware2022.csv")
    numeric_columns = [
        "pdfsize",
        "metadata size",
        "obj",
        "JS",
        "Javascript",
        "launch",
        "AA",
        "OpenAction",
        "EmbeddedFile",
        "RichMedia",
        "ObjStm",
    ]
    for column in numeric_columns:
        pdf_df[column] = pd.to_numeric(pdf_df[column], errors="coerce").fillna(0)
    pdf_df["text"] = pdf_df["text"].fillna("No")
    rows = []

    for _, item in pdf_df.iterrows():
        row = _base_row("pdf", 1 if str(item["Class"]).strip().lower() == "malicious" else 0)
        pdf_size_kb = float(item["pdfsize"])
        text_flag = str(item["text"]).strip().lower() == "yes"
        row.update(
            {
                "size_bytes": int(pdf_size_kb * 1024),
                "entropy": round(
                    min(
                        8.3,
                        4.3
                        + (0.22 * float(item["JS"]))
                        + (0.18 * float(item["Javascript"]))
                        + (0.10 * float(item["EmbeddedFile"]))
                        + (0.06 * float(item["ObjStm"])),
                    ),
                    6,
                ),
                "printable_ratio": 0.58 if text_flag else 0.31,
                "null_ratio": 0.0,
                "control_ratio": 0.01,
                "suspicious_keyword_hits": int(float(item["JS"]) + float(item["Javascript"]) + float(item["launch"])),
                "script_keyword_hits": int(float(item["JS"]) + float(item["Javascript"]) + float(item["OpenAction"])),
                "url_count": int(float(item["AA"]) + float(item["OpenAction"])),
                "has_pdf": 1,
                "pdf_js_count": int(float(item["JS"]) + float(item["Javascript"])),
                "pdf_openaction_count": int(float(item["OpenAction"]) + float(item["AA"])),
                "pdf_embedded_count": int(float(item["EmbeddedFile"]) + float(item["launch"]) + float(item["RichMedia"])),
                "text_length": int(float(item["metadata size"]) + (float(item["obj"]) * 24)),
            }
        )
        rows.append(row)

    return rows


def build_docx_rows(sample_count=2400):
    rng = random.Random(7)
    rows = []

    for _ in range(sample_count):
        label = 1 if rng.random() < 0.42 else 0
        row = _base_row("docx", label)
        if label == 0:
            row.update(
                {
                    "size_bytes": rng.randint(12000, 900000),
                    "entropy": round(rng.uniform(4.6, 6.4), 6),
                    "printable_ratio": round(rng.uniform(0.55, 0.86), 6),
                    "control_ratio": round(rng.uniform(0.0, 0.02), 6),
                    "has_zip": 1,
                    "doc_has_macro": 0,
                    "doc_has_external_link": 0 if rng.random() < 0.88 else 1,
                    "doc_has_embedding": 0 if rng.random() < 0.82 else 1,
                    "url_count": rng.randint(0, 2),
                    "text_length": rng.randint(800, 12000),
                }
            )
        else:
            row.update(
                {
                    "size_bytes": rng.randint(9000, 650000),
                    "entropy": round(rng.uniform(5.6, 7.8), 6),
                    "printable_ratio": round(rng.uniform(0.26, 0.68), 6),
                    "control_ratio": round(rng.uniform(0.01, 0.08), 6),
                    "suspicious_keyword_hits": rng.randint(1, 4),
                    "script_keyword_hits": rng.randint(1, 4),
                    "url_count": rng.randint(1, 5),
                    "base64_blob_count": rng.randint(0, 2),
                    "has_zip": 1,
                    "doc_has_macro": 1 if rng.random() < 0.65 else 0,
                    "doc_has_external_link": 1 if rng.random() < 0.72 else 0,
                    "doc_has_embedding": 1 if rng.random() < 0.58 else 0,
                    "text_length": rng.randint(1000, 20000),
                }
            )
        rows.append(row)

    return rows


def build_json_rows(sample_count=2400):
    rng = random.Random(99)
    rows = []

    for _ in range(sample_count):
        label = 1 if rng.random() < 0.38 else 0
        row = _base_row("json", label)
        if label == 0:
            row.update(
                {
                    "size_bytes": rng.randint(300, 180000),
                    "entropy": round(rng.uniform(3.4, 5.9), 6),
                    "printable_ratio": round(rng.uniform(0.78, 0.98), 6),
                    "control_ratio": 0.0,
                    "url_count": rng.randint(0, 2),
                    "has_zip": 0,
                    "is_json_valid": 1 if rng.random() < 0.97 else 0,
                    "json_command_fields": 0 if rng.random() < 0.9 else 1,
                    "json_suspicious_values": 0 if rng.random() < 0.84 else 1,
                    "text_length": rng.randint(120, 40000),
                }
            )
        else:
            row.update(
                {
                    "size_bytes": rng.randint(250, 240000),
                    "entropy": round(rng.uniform(4.5, 7.4), 6),
                    "printable_ratio": round(rng.uniform(0.52, 0.93), 6),
                    "control_ratio": round(rng.uniform(0.0, 0.04), 6),
                    "suspicious_keyword_hits": rng.randint(1, 4),
                    "script_keyword_hits": rng.randint(1, 5),
                    "url_count": rng.randint(1, 6),
                    "base64_blob_count": rng.randint(1, 4),
                    "is_json_valid": 1 if rng.random() < 0.8 else 0,
                    "json_command_fields": rng.randint(1, 4),
                    "json_suspicious_values": rng.randint(1, 5),
                    "text_length": rng.randint(300, 60000),
                }
            )
        rows.append(row)

    return rows


def build_training_dataframe():
    rows = []
    rows.extend(build_exe_rows())
    rows.extend(build_pdf_rows())
    rows.extend(build_docx_rows())
    rows.extend(build_json_rows())
    return pd.DataFrame(rows)


def main():
    df = build_training_dataframe()
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=240,
        random_state=42,
        max_depth=18,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=1,
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print("Saved dataset:", DATASET_PATH)
    print("Saved model:", MODEL_PATH)
    print("Rows:", len(df))
    print(classification_report(y_test, predictions, digits=4))

    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
        },
        MODEL_PATH,
    )


if __name__ == "__main__":
    main()
