// What a vault item is (its kind) and what it's about (its tags).
//
// Every item has exactly one kind: id · card · pass · photo · file. The kind is
// sealed in the item's encrypted index entry. Items sealed by builds before 2.0
// carry none, so it's inferred from what else is there (an ID summary, a card
// summary, a pass summary, an image type) and written back the next time that
// entry is re-sealed for another reason (a rename, a pin), never in bulk.
//
// Tags are optional labels (the categories of 1.x, same ids): suggested from the
// name when something is added, shown as a small label, filterable. An old
// item's category becomes its tag on read, except the two that never named a
// subject: "other" (no tag) and "passes" (now the pass kind).

export const KINDS = [
  { id: "id", label: "IDs", one: "ID", icon: "idcard" },
  { id: "card", label: "Cards", one: "Payment card", icon: "card" },
  { id: "pass", label: "Passes", one: "Wallet pass", icon: "ticket" },
  { id: "photo", label: "Photos", one: "Photo", icon: "image" },
  { id: "file", label: "Files", one: "File", icon: "file" },
];
export const KIND_IDS = KINDS.map((k) => k.id);
export const kindOf = (id) => KINDS.find((k) => k.id === id) || KINDS[KINDS.length - 1];

export const TAGS = [
  { id: "identity", label: "Identity", icon: "idcard" },
  { id: "health", label: "Health", icon: "health" },
  { id: "money", label: "Money", icon: "money" },
  { id: "home", label: "Home", icon: "home" },
  { id: "personal", label: "Personal", icon: "user" },
];
export const TAG_IDS = TAGS.map((t) => t.id);
export const tagOf = (id) => TAGS.find((t) => t.id === id) || null;

const ID_TYPE = "application/vnd.humid.id+json";
const CARD_TYPE = "application/vnd.humid.card+json";
const PASS_TYPE = "application/vnd.apple.pkpass";

/** The kind a file of this media type (and name) is sealed as. */
export function kindFromType(type = "", name = "") {
  if (type === ID_TYPE) return "id";
  if (type === CARD_TYPE) return "card";
  if (type === PASS_TYPE || /\.pkpass$/i.test(name)) return "pass";
  if (String(type).startsWith("image/")) return "photo";
  return "file";
}

/** The kind of an index entry (sealed or inferred), always one of KIND_IDS. */
export function inferKind(entry = {}) {
  if (KIND_IDS.includes(entry.kind)) return entry.kind;
  if (entry.idInfo) return "id";
  if (entry.cardInfo) return "card";
  if (entry.passInfo) return "pass";
  return kindFromType(entry.type, entry.name);
}

/** The tags of an index entry: its own, or the 1.x category it was filed under. */
export function inferTags(entry = {}) {
  if (Array.isArray(entry.tags)) return entry.tags.filter((t) => TAG_IDS.includes(t));
  return TAG_IDS.includes(entry.category) ? [entry.category] : [];
}

/**
 * A decoded index entry with its kind and tags settled. `kindInferred` says the kind
 * wasn't in the sealed entry (so the next re-seal of the entry writes it).
 */
export function classify(entry) {
  const kind = inferKind(entry);
  const { category, ...rest } = entry;
  return { ...rest, kind, tags: inferTags(entry), kindInferred: !KIND_IDS.includes(entry.kind) };
}

// Suggest a tag for a new document from its name and type, so nothing is filed as
// "Identity" by default. The person can always change it; when nothing matches, the
// answer is null, never a guess dressed up as a fact.
const RULES = [
  ["identity", /passport|driver'?s?[\s_-]*licen[cs]e|\blicen[cs]e\b|\bid\b|\bid[\s_-]*card|identity|birth[\s_-]*cert|social[\s_-]*security|\bssn\b|\bvisa\b|residen(ce|t)[\s_-]*(card|permit)|citizenship|naturali[sz]ation|green[\s_-]*card/i],
  ["health", /medical|health|\blab\b|lab[\s_-]*results?|vaccin|immuni[sz]|prescription|\brx\b|insurance[\s_-]*card|doctor|hospital|clinic|dental|vision|allerg|covid/i],
  ["money", /\bbank|statement|\btax|\bw-?2\b|\b1099\b|invoice|receipt|payslip|pay[\s_-]*stub|salary|\bloan|credit|brokerage|\b401k\b|\bira\b|investment|budget/i],
  ["home", /\blease|\bdeed|mortgage|\btitle\b|\brent(al)?\b|property|\bhoa\b|warranty|utility|insurance[\s_-]*polic|\bhome\b|\bhouse\b|apartment|vehicle|\bcar\b|registration/i],
  ["personal", /\bwill\b|testament|marriage|divorce|diploma|degree|transcript|resume|\bcv\b|letter|contacts?\b|journal|\bnotes?\b/i],
];

/** One of TAG_IDS, or null when nothing in the name says what it's about. */
export function guessTag(name = "") {
  const n = String(name).replace(/\.[a-z0-9]{1,5}$/i, "");
  for (const [tag, re] of RULES) if (re.test(n)) return tag;
  return null;
}

/** The tag suggested for a new item of this kind, from its name: IDs and cards have a natural one. */
export function suggestTags(kind, name = "") {
  if (kind === "id") return ["identity"];
  if (kind === "card") return ["money"];
  if (kind === "pass") return [];
  const t = guessTag(name);
  return t ? [t] : [];
}
