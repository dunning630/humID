---
"@humid/mobile": patch
---

The guided camera asks for the long side only, so a portrait phone no longer loses the top and bottom of the document in the preview (a width and a height together make a browser cut the frame to that shape); if the preview still comes back turned the wrong way for the screen it asks once more with both sizes. The shaky-camera test fixture has 16 distinct views, so the stability test cannot pass or fail on two equal frames by chance.
