// Suggest a category for a new document from its name and type, so nothing is
// filed as "Identity" by default. The person can always change it; when nothing
// matches, the answer is "other", never a guess dressed up as a fact.

const RULES = [
  ["identity", /passport|driver'?s?[\s_-]*licen[cs]e|\blicen[cs]e\b|\bid\b|\bid[\s_-]*card|identity|birth[\s_-]*cert|social[\s_-]*security|\bssn\b|\bvisa\b|residen(ce|t)[\s_-]*(card|permit)|citizenship|naturali[sz]ation|green[\s_-]*card/i],
  ["health", /medical|health|\blab\b|lab[\s_-]*results?|vaccin|immuni[sz]|prescription|\brx\b|insurance[\s_-]*card|doctor|hospital|clinic|dental|vision|allerg|covid/i],
  ["money", /\bbank|statement|\btax|\bw-?2\b|\b1099\b|invoice|receipt|payslip|pay[\s_-]*stub|salary|\bloan|credit|brokerage|\b401k\b|\bira\b|investment|budget/i],
  ["home", /\blease|\bdeed|mortgage|\btitle\b|\brent(al)?\b|property|\bhoa\b|warranty|utility|insurance[\s_-]*polic|\bhome\b|\bhouse\b|apartment|vehicle|\bcar\b|registration/i],
  ["personal", /\bwill\b|testament|marriage|divorce|diploma|degree|transcript|resume|\bcv\b|letter|contacts?\b|journal|\bnotes?\b/i],
];

/** One of: identity, health, money, home, personal, other. */
export function guessCategory(name = "", type = "") {
  if (type === "application/vnd.apple.pkpass" || /\.pkpass$/i.test(name)) return "passes";
  const n = String(name).replace(/\.[a-z0-9]{1,5}$/i, "");
  for (const [category, re] of RULES) if (re.test(n)) return category;
  return "other";
}
