// Open a link outside HumID: the pass shop, a map, a phone number. Only https,
// tel and mailto links are ever opened; anything else is ignored. (A fuller
// version lives with the native shell; this one is the browser fallback.)
export function openExternal(url) {
  if (typeof url !== "string" || !/^(https:|tel:|mailto:)/i.test(url)) return;
  try { window.open(url, "_blank", "noopener,noreferrer"); } catch { /* blocked: nothing opens */ }
}
