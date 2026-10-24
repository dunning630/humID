-- anon: access + relay (SERVER.md §1). Knows no accounts, ever: no table here has an account id.
-- Times: days only where a time isn't needed; relay arrival to the minute. Retention in src/anon/mod.rs.

CREATE TABLE access_codes (
    hash          bytea PRIMARY KEY,                             -- H(access-code, code)
    batch         text  NOT NULL,
    minted_day    text  NOT NULL,
    used_day      text,
    blinded_hash  bytea,                                          -- a retry with the same request gets the same signature
    kid           bytea
);

-- Blind-signing keys, by purpose. The private half is sealed under the HSM seal key and erased
-- once issuing ends; the row goes at accept_until.
CREATE TABLE blind_keys (
    kid           bytea PRIMARY KEY,                             -- SHA3-512(spki)[0..32]
    purpose       text  NOT NULL CHECK (purpose IN ('pass', 'post')),
    spki          bytea NOT NULL,
    sealed_sk     bytea,                                          -- NULL once issuing ended
    issue_until   bigint NOT NULL,
    accept_until  bigint NOT NULL
);

CREATE TABLE spent (
    id            bytea PRIMARY KEY,                             -- H(spent, token)
    kid           bytea NOT NULL,
    accept_until  bigint NOT NULL,                                -- deleted then (4.x kept these forever)
    day           text  NOT NULL
);

-- Live-check statements from core already used for tokens (each buys one batch).
CREATE TABLE used_checks (
    proof_hash    bytea PRIMARY KEY,
    expires_at    bigint NOT NULL
);

CREATE TABLE relay_objects (
    id            bigserial PRIMARY KEY,
    box           bytea  NOT NULL CHECK (length(box) = 16),
    prefix        integer NOT NULL,                              -- the box's first prefix_bits bits
    at            bigint NOT NULL,                                -- to the minute
    size          integer NOT NULL,
    ack_hash      bytea  NOT NULL,                                -- H(relay-token, ack token): only the recipient can derive it
    retract_hash  bytea,                                          -- H(relay-token, retract token): only the sender has it
    wire          bytea  NOT NULL
);
CREATE INDEX relay_prefix ON relay_objects (prefix, id);
CREATE INDEX relay_box ON relay_objects (box);
CREATE INDEX relay_at ON relay_objects (at);

CREATE TABLE push_subs (
    token_hash    bytea PRIMARY KEY,
    token         bytea NOT NULL,                                 -- sealed push token (sender stubbed)
    prefixes      integer[] NOT NULL,
    refreshed_at  bigint NOT NULL
);

CREATE TABLE day_counts (
    day           text PRIMARY KEY,
    passes        bigint NOT NULL DEFAULT 0,
    post_tokens   bigint NOT NULL DEFAULT 0,
    deposits      bigint NOT NULL DEFAULT 0
);
