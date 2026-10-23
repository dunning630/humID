---
"@humid/mobile": patch
---

Accessibility. Every layer that takes the screen (a sheet, a pushed screen, the document viewer, the live-check overlay and the chip reader) is modal now: focus moves into it, Tab and Shift+Tab stay inside it, everything behind it is `inert`, and focus goes back to what opened it when it closes (APP-12). Welcome and Lock have an h1 (the wordmark); section headings under a screen's title are h2, styled as before; the viewer's header is no longer a second page banner. In the light theme mint text is darker (#0E6B47), so it meets 4.5:1 on its own wash over every surface (the active filter chip was 4.26:1). Segmented controls, the search field and "More filters" are 44 px like every other control. The type comment no longer claims iOS Dynamic Type works without code.
