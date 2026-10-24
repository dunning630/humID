-- core: phone attestation (crates/humid-attest; SERVER.md §2.3, §12). 0001 and 0002 are frozen.

-- What each device's platform attestation proved, kept with the device (revoked devices keep
-- theirs, like their certificate). Android: the chain, re-checked against Google's status
-- list at every sign-in and on a schedule. iOS: the App Attest key and the highest assertion
-- counter accepted, so every live check's assertion must count up.
CREATE TABLE device_attestations (
    device              bytea  PRIMARY KEY REFERENCES devices(id),
    kind                text   NOT NULL CHECK (kind IN ('android', 'apple')),
    detail              jsonb  NOT NULL,                         -- humid-attest's summary (level, versions, app)
    chain               jsonb,                                   -- android: the DER chain, leaf first (base64url)
    app_attest_key      bytea  CHECK (app_attest_key IS NULL OR length(app_attest_key) = 65),
    app_attest_counter  bigint NOT NULL DEFAULT 0,
    verified_at         bigint NOT NULL,
    next_check_at       bigint,                                  -- android: the next scheduled re-check
    CHECK ((kind = 'android') = (chain IS NOT NULL)),
    CHECK ((kind = 'apple') = (app_attest_key IS NOT NULL))
);
CREATE INDEX device_attestations_due ON device_attestations (next_check_at) WHERE kind = 'android';

-- Core's cached copy of Google's attestation status list, as fetched (or imported), with the
-- fetch time, signed by core's statement key (label "HUMID-PQ2 attestation-status"), so the
-- database alone can't drop an entry or freshen an old copy. Forward-only by fetched_at.
CREATE TABLE attest_status (
    one           boolean PRIMARY KEY DEFAULT true CHECK (one),
    fetched_at    bigint NOT NULL,
    list          bytea  NOT NULL,
    sig           bytea  NOT NULL
);
