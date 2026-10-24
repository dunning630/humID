-- keys: the key-share service (SERVER.md §1, §3). Kept apart from core on purpose: it is the split.
-- Never an envelope, a name, or an account key. Every table has a retention rule in src/keys/mod.rs.

CREATE TABLE shares (
    object        bytea PRIMARY KEY CHECK (length(object) = 32),
    account       bytea NOT NULL CHECK (length(account) = 32),
    wrapped       bytea NOT NULL,                                -- under the HSM share KEK (and the fuse, if fused)
    fused         boolean NOT NULL DEFAULT false,                -- also under the account's Check-in fuse key
    created_at    bigint NOT NULL,
    released      bigint NOT NULL DEFAULT 0,
    last_released_at bigint
);
CREATE INDEX shares_account ON shares (account);

CREATE TABLE releases (
    account       bytea  NOT NULL,
    at            bigint NOT NULL
);
CREATE INDEX releases_account_at ON releases (account, at);

-- Every holder proof keys acted on, so each acts once here too.
CREATE TABLE used_proofs (
    proof_hash    bytea PRIMARY KEY,
    expires_at    bigint NOT NULL
);

CREATE TABLE checkin (
    account       bytea PRIMARY KEY CHECK (length(account) = 32),
    state         text   NOT NULL CHECK (state IN ('armed', 'erased')),
    window_ms     bigint NOT NULL,
    max_window_ms bigint NOT NULL,
    grace_ms      bigint NOT NULL,
    armed_at      bigint NOT NULL,
    deadline      bigint NOT NULL,                                -- informational; the fuse in memory decides
    erased_at     bigint,
    erased_count  bigint,
    cleaned       boolean NOT NULL DEFAULT true
);

CREATE TABLE duress_used (
    proof_hash    bytea PRIMARY KEY,
    at            bigint NOT NULL
);
