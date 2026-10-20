---
"@humid/mobile": patch
---

Faster from capture to review. The picture is straightened from the part of the frame the document is in (not the whole 8 MP frame) and at the size that is stored (1600 px cards, 2600 px pages), the clean scan is made in a worker after the review opens, text is read from a smaller card image, the scanner's pages are decoded without a per-byte callback, the "saved" pause is shorter, and the seal step reuses its hash, warms the crypto up while the review is open, and reads the location in parallel (waiting up to three seconds, was five). Nothing is kept or logged that wasn't before. Review now opens before the clean scan is ready: the Seal button waits for it only if the clean scan is the chosen version.
