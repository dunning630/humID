// The trust store: which issuing authorities HumID believes, and why. Pure
// JavaScript, so the same code runs on the server and on the phone.
//
//   mobile IDs (mdoc)   IACA roots from a VICAL (AAMVA's Digital Trust Service
//                       for US and Canadian licenses), plus roots an operator
//                       pins by hand. Each keeps the country, state and
//                       document types its list assigned, and the verifier
//                       holds documents to them (CRD-01).
//   SD-JWT VC issuers   named issuers with the country they speak for, and
//                       x5c roots.
//   passport chips      CSCA certificates from ICAO master lists (read on the
//                       server by csca.js; kept here as DER so the snapshot is
//                       one file).
//
// A list is only as good as the key that signs it, so lists are applied only
// when their signer chains to a provider pinned in advance (providerPins:
// SHA-256 fingerprints confirmed with AAMVA, ICAO or the publishing country
// out of band). The server fetches and relays the signed lists; each device
// re-checks the signature against pins built into the app, so a server can
// relay trust lists but can't add a root of its own to anyone's phone. That
// holds only if devices re-apply the signed lists: a toJSON() snapshot carries
// no signatures and must never be what a server hands a phone.
//
// Lists only move forward: a VICAL older than the one applied (by issue ID,
// then date) is refused, so an attacker who can replay an old list can't
// bring back a root that was removed.

import { readVical, parseCertificate, countryCode, stateCode } from "@humid/mdoc";
import { sha256 } from "@noble/hashes/sha2.js";
import { CredsError, fail } from "./request.js";

export const TRUST_VERSION = 1;
const DAY = 86_400_000;
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const b64 = (u) => { let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = (s) => { const t = atob(s); const o = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) o[i] = t.charCodeAt(i); return o; };
const fpOf = (der) => hex(sha256(der));
const parseDate = (s) => { const d = s ? new Date(s) : null; return d && !Number.isNaN(d.getTime()) ? d : null; };
const asBytes = (x) => (x instanceof Uint8Array ? x : typeof x === "string" && !x.includes("BEGIN") ? unb64(x) : parseCertificate(x).der);

function emptyState() {
  return { v: TRUST_VERSION, rev: 0, iaca: [], sdjwt: [], csca: [], sources: {} };
}

/**
 * A trust store. `state` is a snapshot from toJSON(); omit it to start empty.
 * The store never touches the network or the disk.
 */
export function createTrustStore(state) {
  const s = state ? structuredClone(state) : emptyState();
  if (s.v !== TRUST_VERSION) fail("bad_trust_store", "This trust store was written by a different version of HumID.");
  for (const k of ["iaca", "sdjwt", "csca"]) if (!Array.isArray(s[k])) fail("bad_trust_store", "The trust store is damaged.");
  s.sources ||= {};

  const bump = () => { s.rev += 1; };

  return {
    /**
     * Apply a VICAL. Replaces every root that came from the previous VICAL of
     * the same provider id (`id`, default "aamva"); pinned roots stay.
     *   providerPins: SHA-256 fingerprints of the provider's root or signer (required)
     *   maxAgeDays:   refuse a list dated older than this (default 120)
     *   graceDays:    accept a list this long past its own nextUpdate (default 30)
     * Returns { added, dropped: [{ subject, reason }], issueId, date, nextUpdate }.
     */
    applyVical(bytes, { providerPins, id = "aamva", now = new Date(), maxAgeDays = 120, graceDays = 30 } = {}) {
      if (!providerPins?.length) fail("no_trust", "A VICAL is only as good as its provider: pin the provider's certificate fingerprint first.");
      let list;
      try { list = readVical(bytes, { providerPins, now, maxAgeDays, graceDays }); } catch (e) { fail(e?.code === "stale_vical" ? "stale_vical" : "bad_vical", e.message); }
      if (!list.trusted) fail("bad_vical", "The VICAL isn't signed by a trusted provider.");
      const date = parseDate(list.date);
      if (!date) fail("bad_vical", "The VICAL has no date.");
      if (date > new Date(now.getTime() + DAY)) fail("bad_vical", "The VICAL is dated in the future.");
      if (now - date > maxAgeDays * DAY) fail("stale_vical", "The VICAL is too old to use. Fetch a current one.");
      const next = parseDate(list.nextUpdate);
      if (next && now - next > graceDays * DAY) fail("stale_vical", "The VICAL is long past its own update date. Fetch a current one.");

      const digest = fpOf(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
      const prev = s.sources[`vical:${id}`];
      if (prev) {
        const prevDate = parseDate(prev.date);
        const issue = Number.isSafeInteger(list.issueId) ? list.issueId : null;
        if (issue != null && prev.issueId != null) {
          if (issue < prev.issueId) fail("rollback", "This VICAL is older than the one already applied.");
          if (issue === prev.issueId && digest !== prev.sha256) fail("rollback", "This VICAL has the same issue number as the one applied, but different contents.");
        } else if (prevDate && date < prevDate) fail("rollback", "This VICAL is older than the one already applied.");
        else if (prevDate && +date === +prevDate && digest !== prev.sha256) fail("rollback", "This VICAL has the same date as the one applied, but different contents.");
        if (digest === prev.sha256) return { added: 0, dropped: [], unchanged: true, issueId: list.issueId, date: list.date, nextUpdate: list.nextUpdate };
      }

      const added = [], dropped = [];
      for (const c of list.certificates) {
        let cert;
        try { cert = parseCertificate(c.der); } catch { dropped.push({ subject: null, reason: "unreadable certificate" }); continue; }
        const subject = cert.subject?.CN || null;
        if (!cert.isCa) { dropped.push({ subject, reason: "not a certificate authority" }); continue; }
        if (now > cert.notAfter) { dropped.push({ subject, reason: "expired" }); continue; }
        const listC = countryCode(c.country), certC = countryCode(cert.subject.C);
        const listST = stateCode(c.state), certST = stateCode(cert.subject.ST);
        if (listC && certC && listC !== certC) { dropped.push({ subject, reason: "the list and the certificate name different countries" }); continue; }
        if (listST && certST && listST !== certST) { dropped.push({ subject, reason: "the list and the certificate name different states" }); continue; }
        const country = listC || certC;
        if (!country) { dropped.push({ subject, reason: "no country" }); continue; }
        // A root vouches only for the document types its list names; none named, none trusted.
        const docTypes = Array.isArray(c.docTypes) ? c.docTypes.filter((t) => typeof t === "string") : [];
        if (!docTypes.length) { dropped.push({ subject, reason: "no document types" }); continue; }
        added.push({
          der: b64(cert.der), fingerprint: fpOf(cert.der), country, state: listST || certST || null,
          docTypes,
          authority: typeof c.authority === "string" ? c.authority : null, subject, notAfter: cert.notAfter.toISOString(),
          source: `vical:${id}`,
        });
      }
      s.iaca = [...s.iaca.filter((e) => e.source !== `vical:${id}`), ...added];
      s.sources[`vical:${id}`] = {
        kind: "vical", provider: list.provider || null, issueId: Number.isSafeInteger(list.issueId) ? list.issueId : null,
        date: list.date, nextUpdate: list.nextUpdate, appliedAt: now.toISOString(), sha256: digest,
        signer: list.signer.fingerprint, count: added.length,
      };
      bump();
      return { added: added.length, dropped, issueId: list.issueId, date: list.date, nextUpdate: list.nextUpdate };
    },

    /**
     * Pin one IACA root by hand (a state's published root, before it's in a
     * VICAL). country is required; state is required for US and Canadian roots
     * that will vouch for a jurisdiction.
     */
    pinIaca(certInput, { country, state, docTypes = ["org.iso.18013.5.1.mDL"], note } = {}) {
      if (!Array.isArray(docTypes) || !docTypes.length) fail("bad_certificate", "Say which document types this root may vouch for.");
      let cert;
      try { cert = parseCertificate(asBytes(certInput)); } catch { fail("bad_certificate", "That certificate can't be read."); }
      if (!cert.isCa) fail("bad_certificate", "Only a certificate authority's root can be pinned.");
      const c = countryCode(country) || countryCode(cert.subject.C);
      if (!c) fail("bad_certificate", "Say which country this root speaks for.");
      if (countryCode(cert.subject.C) && countryCode(cert.subject.C) !== c) fail("bad_certificate", "The certificate names a different country.");
      const st = stateCode(state) || stateCode(cert.subject.ST);
      if (stateCode(cert.subject.ST) && st !== stateCode(cert.subject.ST)) fail("bad_certificate", "The certificate names a different state.");
      const fingerprint = fpOf(cert.der);
      s.iaca = s.iaca.filter((e) => !(e.source === "pinned" && e.fingerprint === fingerprint));
      s.iaca.push({ der: b64(cert.der), fingerprint, country: c, state: st || null, docTypes, authority: null, subject: cert.subject.CN || null, notAfter: cert.notAfter.toISOString(), source: "pinned", note: note || null });
      bump();
      return fingerprint;
    },

    /**
     * Name an SD-JWT VC issuer HumID accepts, the country it speaks for, and the
     * credential types (vct) it may issue. Without types, only x5c-signed
     * credentials from it are accepted: a key from its own metadata counts only
     * for listed types (review finding F3).
     */
    addSdJwtIssuer({ iss, country, state, vct, note } = {}) {
      let u;
      try { u = new URL(iss); } catch { fail("bad_issuer", "The issuer must be an https URL."); }
      if (u.protocol !== "https:") fail("bad_issuer", "The issuer must be an https URL.");
      const c = countryCode(country);
      if (!c) fail("bad_issuer", "Say which country this issuer speaks for.");
      if (vct != null && (!Array.isArray(vct) || !vct.length || vct.some((t) => typeof t !== "string" || !t))) fail("bad_issuer", "List the credential types (vct) this issuer may issue.");
      s.sdjwt = [...s.sdjwt.filter((e) => e.iss !== iss), { iss, country: c, state: stateCode(state) || null, vct: vct ? [...vct] : null, note: note || null }];
      bump();
    },

    /** Remove a pinned root or an SD-JWT issuer. Roots from a list leave only with the next list. */
    remove({ fingerprint, iss } = {}) {
      const before = s.iaca.length + s.sdjwt.length + s.csca.length;
      if (fingerprint) { s.iaca = s.iaca.filter((e) => !(e.source === "pinned" && e.fingerprint === fingerprint)); s.csca = s.csca.filter((e) => !(e.source === "pinned" && e.fingerprint === fingerprint)); }
      if (iss) s.sdjwt = s.sdjwt.filter((e) => e.iss !== iss);
      const changed = s.iaca.length + s.sdjwt.length + s.csca.length !== before;
      if (changed) bump();
      return changed;
    },

    /**
     * CSCAs from a master list, already checked by csca.js on the server
     * ([{ der, country }]); replaces that source's previous set.
     */
    setCscas(source, entries, info = {}) {
      if (!/^[a-z0-9:_-]{1,40}$/.test(source)) fail("bad_request", "Name the master list source with letters, digits, - or _.");
      const rows = entries.map((e) => ({ der: b64(asBytes(e.der)), fingerprint: fpOf(asBytes(e.der)), country: countryCode(e.country), notAfter: e.notAfter || null, source }));
      s.csca = [...s.csca.filter((e) => e.source !== source), ...rows.filter((r) => r.country)];
      s.sources[source] = { kind: "master-list", ...info, count: rows.length };
      bump();
    },

    /**
     * What the verifiers take:
     *   trust for verifyCredentialResponse / checkStatus: { iaca, sdjwt: { roots, issuers, resolveKey? } }
     * Expired roots are left out. Pass resolveKey to allow keys from listed
     * issuers' metadata.
     */
    forVerifier({ now = new Date(), resolveKey } = {}) {
      const live = (e) => !e.notAfter || new Date(e.notAfter) >= now;
      const iaca = s.iaca.filter(live).map((e) => ({ cert: unb64(e.der), country: e.country, state: e.state, docTypes: e.docTypes, source: e.source }));
      return {
        iaca,
        // x5c roots for SD-JWT VCs: only roots trusted for that format by name, never a
        // state DMV's mDL root just because it's in the VICAL.
        // issuers is left out when none are named, so x5c-signed credentials under a
        // trusted SD-JWT root still verify (an empty list would refuse them all).
        sdjwt: { roots: iaca.filter((e) => e.docTypes.includes("dc+sd-jwt")), ...(s.sdjwt.length ? { issuers: s.sdjwt.map((e) => ({ iss: e.iss, country: e.country, state: e.state, ...(e.vct ? { vct: e.vct } : {}) })) } : {}), ...(resolveKey ? { resolveKey } : {}) },
      };
    },

    /** CSCA certificates (DER) for passive authentication; the server wraps them as X509Certificate. */
    cscaDers({ now = new Date() } = {}) {
      return s.csca.filter((e) => !e.notAfter || new Date(e.notAfter) >= now).map((e) => unb64(e.der));
    },

    /** What an operator or a health check needs to see. */
    status({ now = new Date() } = {}) {
      const sources = Object.fromEntries(Object.entries(s.sources).map(([k, v]) => {
        const next = parseDate(v.nextUpdate);
        return [k, { ...v, overdue: !!(next && now > next) }];
      }));
      const byState = {};
      for (const e of s.iaca) if (e.state && e.country === "US") byState[e.state] = (byState[e.state] || 0) + 1;
      return {
        rev: s.rev, iaca: s.iaca.length, pinned: s.iaca.filter((e) => e.source === "pinned").length,
        usStates: Object.keys(byState).sort(), sdjwtIssuers: s.sdjwt.length, cscaCountries: [...new Set(s.csca.map((e) => e.country))].sort().length,
        sources,
      };
    },

    /** A snapshot to save. Restore with createTrustStore(snapshot). */
    toJSON() { return structuredClone(s); },

    /** The revision: goes up by one with every change, so a saved copy can't be swapped for an older one unnoticed. */
    get rev() { return s.rev; },
  };
}

/**
 * Restore a saved snapshot, refusing one older than the revision the caller
 * last saw (keep that number somewhere the snapshot's own disk can't change).
 */
export function loadTrustStore(snapshot, { minRev = 0 } = {}) {
  if (!snapshot || typeof snapshot !== "object") fail("bad_trust_store", "The trust store is missing or damaged.");
  if (!Number.isSafeInteger(snapshot.rev) || snapshot.rev < minRev) fail("rollback", "This trust store is older than the last one used.");
  return createTrustStore(snapshot);
}

export { CredsError };
