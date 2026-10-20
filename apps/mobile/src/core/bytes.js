// Bytes and base64, without the slow paths. `Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0))`
// walks a string of millions of characters through an iterator and a callback: about 25x
// slower than a plain loop (280 ms against 10 ms for a 2 MB page in Node; several times
// that on a phone). Pages and photos come through here, so it matters.

/** base64 text → bytes. Uses the platform's own decoder where there is one. */
export function b64Bytes(text) {
  if (typeof Uint8Array.fromBase64 === "function") return Uint8Array.fromBase64(text);
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < out.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** bytes → base64 text. Small chunks: spreading tens of thousands of arguments can overflow the stack on phones. */
export function bytesB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x1000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x1000));
  return btoa(s);
}
