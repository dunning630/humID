---
"@humid/idscan": patch
"@humid/cards": patch
---

Fix a denial of service in reading ID and card text. The MRZ names field used a regex that took exponential time on a name followed by many `<` fillers (about 27 s at 30), which froze the scanner on crafted or misread OCR text. It is now a linear parser with identical results, `<`/`F` trailing-run trimming no longer does quadratic work, and MRZ and card OCR text is bounded in size and line length before it is read.
