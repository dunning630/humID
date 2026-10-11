// @humid/io — getting bytes out of the app. In the native shells a system
// save dialog writes the file (works on iOS and Android content URIs too);
// in a browser it falls back to a download link.

const inTauri = () => typeof globalThis.__TAURI_INTERNALS__?.invoke === "function";

async function nativeSave(bytes, name) {
  // Raw binary body, so a 512 MB file is not converted to JSON on the way.
  const saved = await globalThis.__TAURI_INTERNALS__.invoke("save_bytes", bytes, {
    headers: { "x-humid-name": encodeURIComponent(name) },
  });
  return saved ? { saved: true, where: saved } : { saved: false };
}

function browserSave(bytes, name, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
  return { saved: true, where: null };
}

export async function saveBytes(bytes, name, type = "application/octet-stream") {
  return inTauri() ? nativeSave(bytes, name) : browserSave(bytes, name, type);
}

export const readFile = async (file) => new Uint8Array(await file.arrayBuffer());
