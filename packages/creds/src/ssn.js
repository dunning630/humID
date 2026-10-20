// US Social Security numbers: what can honestly be checked.
//
// There is no SSN credential to verify. The card isn't signed, isn't in any
// wallet, and no public service confirms a number for anyone who asks. Two
// things are possible:
//
//   1. Structure (here, anywhere): whether a string could be an SSN at all.
//      It says nothing about whether it was issued, or to whom.
//   2. A registry match through SSA's eCBSV (Electronic Consent Based SSN
//      Verification): yes/no for a number + name + date of birth, which fields
//      don't match, and a death indicator. Only "permitted entities" may use
//      it: financial institutions under Gramm-Leach-Bliley section 509 and
//      their service providers, subsidiaries, affiliates, agents,
//      subcontractors or assignees (Economic Growth, Regulatory Relief, and
//      Consumer Protection Act, section 215). Each check needs the number
//      holder's signed consent (wet or electronic), and there is an annual,
//      volume-tiered fee. HumID can't use it unless the operator is, or
//      contracts with, a permitted entity; the transport is theirs.
//
// HumID never stores an SSN: not in a result, a log line, or an error. Hashing
// doesn't help (a billion possibilities hash in seconds), so nothing derived
// from the number is kept either.

import { CredsError, fail } from "./request.js";

/** Known never-valid numbers (SSA): the Woolworth wallet card and the 1940s advertising number. */
const RETIRED = new Set(["078051120", "219099999"]);

/**
 * Could this be an SSN? Returns { valid, reason }, never the number.
 * Area 001–899 except 666 (900–999 are ITINs or never issued), group 01–99, serial 0001–9999.
 */
export function checkSsnFormat(input) {
  const s = String(input ?? "").trim();
  if (!/^\d{3}-?\d{2}-?\d{4}$/.test(s) && !/^\d{3} \d{2} \d{4}$/.test(s)) return { valid: false, reason: "An SSN is nine digits, written 123-45-6789." };
  const d = s.replace(/\D/g, "");
  const area = +d.slice(0, 3), group = +d.slice(3, 5), serial = +d.slice(5);
  if (area === 0 || area === 666 || area >= 900) return { valid: false, reason: "That number's first three digits are never issued as an SSN." };
  if (group === 0) return { valid: false, reason: "That number's middle two digits are never 00." };
  if (serial === 0) return { valid: false, reason: "That number's last four digits are never 0000." };
  if (RETIRED.has(d)) return { valid: false, reason: "That number was published and is never valid." };
  return { valid: true, reason: null };
}

/**
 * An eCBSV verifier. `send` is the operator's own client for SSA's service
 * (it carries their credentials and follows SSA's technical specification);
 * it receives { ssn, firstName, middleName, lastName, dateOfBirth } and must
 * resolve { match: boolean, mismatched?: string[], deceased?: boolean }.
 * permittedEntity: the operator asserts it is (or contracts with) one.
 */
export function ecbsvVerifier({ send, permittedEntity = false } = {}) {
  return {
    async verify({ ssn, firstName, middleName = "", lastName, dateOfBirth, consent } = {}) {
      if (!permittedEntity || typeof send !== "function") {
        fail("not_permitted", "SSN checks go through SSA's eCBSV, which only financial institutions and their service providers may use. This server isn't set up as one.");
      }
      const f = checkSsnFormat(ssn);
      if (!f.valid) fail("bad_ssn", f.reason);
      if (!firstName || !lastName || !/^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth || "")) fail("bad_request", "A check needs first name, last name and date of birth (YYYY-MM-DD).");
      if (!consent || !["wet", "electronic"].includes(consent.method) || !consent.signedAt || !consent.text) {
        fail("no_consent", "SSA requires the number holder's signed consent (wet or electronic) for each check.");
      }
      let answer;
      try {
        answer = await send({ ssn: String(ssn).replace(/\D/g, ""), firstName, middleName, lastName, dateOfBirth });
      } catch {
        fail("registry_unavailable", "The SSN check couldn't be completed. Try again later."); // never echo the error: it may contain the number
      }
      if (!answer || typeof answer.match !== "boolean") fail("registry_unavailable", "The SSN check gave no answer.");
      return {
        type: "ssn", via: "eCBSV", assurance: "registry", match: answer.match,
        mismatched: Array.isArray(answer.mismatched) ? answer.mismatched.filter((x) => ["ssn", "name", "dateOfBirth"].includes(x)) : [],
        deceased: answer.deceased === true, checkedAt: new Date().toISOString(),
        consent: { method: consent.method, signedAt: consent.signedAt },
      };
    },
  };
}

export { CredsError };
