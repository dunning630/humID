---
"@humid/mobile": patch
---

Spacing on the token grid. The screens' 190 inline `style={{ marginTop: N }}` become `mt-N`/`mb-N` utility classes mapped to `--s-1…--s-8`, and the off-grid margins (6, 10, 14, 18, 22 px) snap to the nearest grid step, so gaps between cards are even. Each moves by at most 2 px. The Recovery screen no longer says the proof rule twice.
