// "Clean scan": a straightened photo of a page made to look like it came off a flatbed
// scanner. The camera sees a page lit unevenly (a shadow from the phone, a lamp to
// one side, warm room light); a scanner lights it evenly and white. So:
//   1. estimate the light falling on the page, block by block (the brighter part of
//      each block is paper), smoothed into a gentle field;
//   2. divide it out, so the paper is the same white everywhere and the ink keeps its
//      darkness relative to the paper around it (shadows go, text doesn't fade);
//   3. take off a warm or cool cast, a little (paper is white; only mild casts are
//      corrected, so a coloured form stays coloured);
//   4. set the levels: paper to white, the darkest ink to near black.
// Colours keep their hue: every step scales R, G and B by the same amount except the
// small cast correction. Pure functions on RGBA { width, height, data }, tested in Node
// (tests/scanclean.test.js).

const luma = (d, i) => (d[i] * 77 + d[i + 1] * 150 + d[i + 2] * 29) >> 8;
// the brightest of R, G, B: what paper of any colour has most of, so evening the light
// on it whitens white paper and leaves a coloured form its colour (nothing clips)
const top = (d, i) => Math.max(d[i], d[i + 1], d[i + 2]);

/**
 * The light on the page: per block, the level 90% of its pixels are darker than
 * (paper, not ink, even in a block that's mostly text), then spread and smoothed over
 * neighbouring blocks. Returns { bw, bh, B, field (Float32Array, one value per block) }.
 */
export function lightField({ width: W, height: H, data }, { blocks = 56 } = {}) {
  const B = Math.max(8, Math.round(Math.max(W, H) / blocks));
  const bw = Math.ceil(W / B), bh = Math.ceil(H / B);
  const hist = new Uint32Array(bw * bh * 64), count = new Uint32Array(bw * bh);
  for (let y = 0; y < H; y += 2) {
    const by = (y / B) | 0;
    for (let x = 0; x < W; x += 2) {
      const k = by * bw + ((x / B) | 0);
      hist[k * 64 + (top(data, (y * W + x) * 4) >> 2)]++; count[k]++;
    }
  }
  let field = new Float32Array(bw * bh);
  for (let k = 0; k < bw * bh; k++) {
    const want = count[k] * 0.9;
    let n = 0, v = 63;
    for (let b = 0; b < 64; b++) { n += hist[k * 64 + b]; if (n >= want) { v = b; break; } }
    field[k] = v * 4 + 2;
  }
  // spread the brighter neighbour into a block that's nearly all ink (a heading, a photo's edge)
  const spread = new Float32Array(field.length);
  for (let y = 0; y < bh; y++) for (let x = 0; x < bw; x++) {
    let m = field[y * bw + x], sum = 0, n = 0;
    for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
      const yy = y + dy, xx = x + dx;
      if (yy < 0 || xx < 0 || yy >= bh || xx >= bw) continue;
      sum += field[yy * bw + xx]; n++;
    }
    // only lift a block well below its neighbours' average: a real shadow edge is gradual
    const avg = sum / n;
    spread[y * bw + x] = m < avg * 0.8 ? avg : m;
  }
  field = spread;
  // smooth: light changes gently across a page
  for (let pass = 0; pass < 1; pass++) {
    const out = new Float32Array(field.length);
    for (let y = 0; y < bh; y++) for (let x = 0; x < bw; x++) {
      let sum = 0, n = 0;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        const yy = y + dy, xx = x + dx;
        if (yy < 0 || xx < 0 || yy >= bh || xx >= bw) continue;
        sum += field[yy * bw + xx]; n++;
      }
      out[y * bw + x] = sum / n;
    }
    field = out;
  }
  return { bw, bh, B, field };
}

/** The field's value at pixel (x, y), interpolated between block centres. */
function sample({ bw, bh, B, field }, x, y) {
  const fx = Math.min(bw - 1, Math.max(0, x / B - 0.5)), fy = Math.min(bh - 1, Math.max(0, y / B - 0.5));
  const x0 = fx | 0, y0 = fy | 0, x1 = Math.min(bw - 1, x0 + 1), y1 = Math.min(bh - 1, y0 + 1);
  const ax = fx - x0, ay = fy - y0;
  const top = field[y0 * bw + x0] * (1 - ax) + field[y0 * bw + x1] * ax;
  const bot = field[y1 * bw + x0] * (1 - ax) + field[y1 * bw + x1] * ax;
  return top * (1 - ay) + bot * ay;
}

/**
 * How much of the picture looks like paper: the share of blocks whose light is close
 * to the brightest. A page of text is mostly paper (high); a photo, a dark card or a
 * screen isn't (low), and a clean scan of it shouldn't be suggested.
 */
export function paperShare(lf) {
  const sorted = Float32Array.from(lf.field).sort();
  const top = sorted[Math.floor(sorted.length * 0.95)] || 1;
  let n = 0;
  for (const v of lf.field) if (v >= top * 0.72 && v >= 90) n++;
  return n / lf.field.length;
}

/**
 * The clean scan of an RGBA picture. Returns { width, height, data (new), paper }
 * (paper: paperShare, so the caller can decide whether to suggest it).
 *   white     what the paper becomes (before levels)
 *   maxGain   the most any spot is brightened (deep shadow stays a little grey rather
 *             than turning into noise)
 */
export function cleanScan(img, { white = 240, maxGain = 3.2, cast = true } = {}) {
  const { width: W, height: H, data } = img;
  const lf = lightField(img);
  const out = new Uint8ClampedArray(data.length);
  // 1–2: even the light
  const gainRow = new Float32Array(W);
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) gainRow[x] = Math.min(maxGain, Math.max(0.8, white / Math.max(1, sample(lf, x, y))));
    for (let x = 0, i = y * W * 4; x < W; x++, i += 4) {
      const g = gainRow[x];
      out[i] = data[i] * g; out[i + 1] = data[i + 1] * g; out[i + 2] = data[i + 2] * g; out[i + 3] = 255;
    }
  }
  // 3: the paper's colour, from the pixels that are now paper
  let r = 0, g = 0, b = 0, n = 0;
  for (let i = 0; i < out.length; i += 16) {
    const l = luma(out, i);
    if (l >= white - 18 && l < 255) { r += out[i]; g += out[i + 1]; b += out[i + 2]; n++; }
  }
  let kr = 1, kg = 1, kb = 1;
  if (cast && n > 50) {
    r /= n; g /= n; b /= n;
    // lift the weaker channels toward the strongest (never dim one: paper must end up white)
    const m = Math.max(r, g, b);
    const clamp = (k) => Math.min(1.2, Math.max(1, k));
    kr = clamp(m / r); kg = clamp(m / g); kb = clamp(m / b);
  }
  // 4: levels: the darkest 0.5% to black (but never lifting a light page's ink to black
  // past a point), paper to white
  const hist = new Uint32Array(256);
  for (let i = 0; i < out.length; i += 8) hist[luma(out, i)]++;
  const total = out.length / 8;
  let lo = 0;
  for (let acc = 0; lo < 255; lo++) { acc += hist[lo]; if (acc >= total * 0.005) break; }
  lo = Math.min(lo, 70);
  const hi = white - 6;
  const scale = 255 / Math.max(32, hi - lo);
  const lut = new Uint8ClampedArray(256 * 3);
  for (let v = 0; v < 256; v++) {
    for (const [c, k] of [[0, kr], [1, kg], [2, kb]]) {
      let t = (v * k - lo) * scale;
      // a soft shoulder near white: paper grain and faint smudges go, light ink stays
      if (t > 225) t = 225 + (t - 225) * 2;
      lut[c * 256 + v] = t;
    }
  }
  for (let i = 0; i < out.length; i += 4) {
    out[i] = lut[out[i]]; out[i + 1] = lut[256 + out[i + 1]]; out[i + 2] = lut[512 + out[i + 2]];
  }
  return { width: W, height: H, data: out, paper: paperShare(lf) };
}
