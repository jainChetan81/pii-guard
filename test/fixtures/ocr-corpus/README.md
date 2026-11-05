# Synthetic OCR corpus

All values are fabricated for testing and are not real credentials.
Some identifiers use checksum-valid test values or realistic formats.
The labels contain rule IDs only, not planted values.
Run `python3 scripts/make-ocr-corpus.py` from the repository root to regenerate.
The generator needs Python 3, `google-chrome`, and `ffmpeg` on PATH.
It deletes existing PNG and JPG files in this directory before generating fixtures.
Values use a fixed random seed; rendering can vary across Chrome and font versions.
Small and low-contrast images intentionally challenge OCR and may not be recognized fully.
