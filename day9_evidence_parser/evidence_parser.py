"""
day9_evidence_parser/evidence_parser.py

Day 9 — Evidence Parser Tool

Accepts a folder of files (.txt, .json, .csv), extracts metadata for
each (file name, size, type, creation/modification date), and writes a
forensic report to evidence_report.json.

Usage:
    python evidence_parser.py [path_to_evidence_folder] [output_path]
"""

import os
import sys
import json
import hashlib
from datetime import datetime

SUPPORTED_EXTENSIONS = {".txt", ".json", ".csv"}


def compute_sha256(file_path: str) -> str:
    """Compute a SHA-256 hash of the file contents (standard forensic practice
    for establishing evidence integrity / chain of custody)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_file_metadata(file_path: str) -> dict:
    stat = os.stat(file_path)
    name = os.path.basename(file_path)
    ext = os.path.splitext(name)[1].lower()

    # Creation time isn't reliably available on all filesystems/platforms;
    # st_ctime is metadata-change time on Linux. We report both explicitly
    # rather than pretending st_ctime is true creation time.
    return {
        "file_name": name,
        "file_type": ext.lstrip("."),
        "size_bytes": stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "metadata_changed_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "sha256": compute_sha256(file_path),
    }


def scan_evidence_folder(folder_path: str) -> dict:
    if not os.path.isdir(folder_path):
        raise NotADirectoryError(f"{folder_path} is not a valid directory")

    files_report = []
    skipped = []

    for entry in sorted(os.listdir(folder_path)):
        full_path = os.path.join(folder_path, entry)
        if not os.path.isfile(full_path):
            continue

        ext = os.path.splitext(entry)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            skipped.append(entry)
            continue

        try:
            files_report.append(get_file_metadata(full_path))
        except OSError as e:
            print(f"[evidence_parser] Could not read {entry}: {e}")

    print(f"[evidence_parser] Processed {len(files_report)} evidence files, "
          f"skipped {len(skipped)} unsupported files.")

    return {
        "evidence_folder": os.path.abspath(folder_path),
        "generated_at": datetime.now().isoformat(),
        "total_files": len(files_report),
        "skipped_unsupported_files": skipped,
        "files": files_report,
    }


def main():
    folder_path = sys.argv[1] if len(sys.argv) > 1 else "../sample_data/evidence_folder"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "evidence_report.json"

    report = scan_evidence_folder(folder_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[evidence_parser] Written to {output_path}")


if __name__ == "__main__":
    main()
