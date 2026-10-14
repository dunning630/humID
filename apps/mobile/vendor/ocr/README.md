# MRZ OCR model

`mrz.traineddata` is the integer ("fast") Tesseract LSTM model for
machine-readable zones from
[DoubangoTelecom/tesseractMRZ](https://github.com/DoubangoTelecom/tesseractMRZ)
(`tessdata_fast/mrz.traineddata`), trained on more than 7,000 real MRZ images.
BSD-3-Clause, see `LICENSE-tesseractMRZ.txt`.

```
sha256  ece2a54f125a73792f9cec74e6f8e62f6e5e00c7f19153ba865af689be5b5f01  mrz.traineddata
size    1,452,847 bytes
```

`apps/mobile/build.mjs` checks this hash and copies the model to
`dist/assets/ocr/`, next to the Tesseract worker and WebAssembly core from
`tesseract.js` / `tesseract.js-core` (Apache-2.0). The app loads it only when
someone scans a passport or ID card; nothing is downloaded at run time.

To replace it, put the new file here, update the hash in this README and in
`build.mjs` (`MRZ_MODEL_SHA256`), and run `node --test tests/idscan.test.js`
plus the browser check in `tests/browser/idscan.mjs`.
