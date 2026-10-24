-- core: identity + vault + ledger + recovery, one database (SERVER.md §1, §4).
-- Fresh schema for 5.0: no 4.x tables, no migrations from 4.x. Times are epoch ms (bigint).
-- Every table has a retention rule in src/core/retention.rs (checked by a test).

CREATE TABLE accounts (
    id            bytea PRIMARY KEY CHECK (length(id) = 32),     -- key_id(account_vk)
    account_vk    bytea NOT NULL,                                -- ML-DSA-87, PQ2 encoding
    kem_pk        bytea NOT NULL,                                -- hybrid KEM, PQ2 encoding
    status        text  NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed')),
    created_at    bigint NOT NULL,
    closed_at     bigint,
    lockdown_at   bigint,                                        -- duress lockdown (silent)
    last_duress_at bigint,
    object_rev    bigint NOT NULL DEFAULT 0,                     -- /sync: bumped on every object change
    devices_rev   bigint NOT NULL DEFAULT 0,
    recovery_rev  bigint NOT NULL DEFAULT 0
);

CREATE TABLE devices (
    id            bytea PRIMARY KEY CHECK (length(id) = 32),     -- key_id(device_vk)
    account       bytea NOT NULL REFERENCES accounts(id),
    cert          jsonb NOT NULL,                                -- the account-signed DeviceCert
    proven        text  NOT NULL,                                -- what the attestation proved
    platform      text  NOT NULL DEFAULT '',
    via           text  NOT NULL CHECK (via IN ('register', 'link', 'recovery')),
    enrolled_at   bigint NOT NULL,
    last_seen_at  bigint,
    revoked_at    bigint
);
CREATE INDEX devices_account ON devices (account) WHERE revoked_at IS NULL;

CREATE TABLE sessions (
    token_hash    bytea PRIMARY KEY,                             -- H(session-token, token); the token is never stored
    account       bytea NOT NULL REFERENCES accounts(id),
    device        bytea NOT NULL REFERENCES devices(id),
    th            bytea NOT NULL,                                -- the HTP transcript the login was bound to
    created_at    bigint NOT NULL,
    last_used_at  bigint NOT NULL,
    expires_at    bigint NOT NULL,
    revoked_at    bigint,
    duress        boolean NOT NULL DEFAULT false
);
CREATE INDEX sessions_account ON sessions (account) WHERE revoked_at IS NULL;

CREATE TABLE nonces (
    nonce         bytea PRIMARY KEY CHECK (length(nonce) = 32),
    kind          text  NOT NULL CHECK (kind IN ('login', 'step-up')),
    account       bytea,                                          -- login: the account asked about (may not exist)
    device        bytea,
    session       bytea,                                          -- step-up: the session it was issued to
    expires_at    bigint NOT NULL
);
CREATE INDEX nonces_session ON nonces (session);
CREATE INDEX nonces_device ON nonces (device);

CREATE TABLE objects (
    id            bytea PRIMARY KEY CHECK (length(id) = 32),
    account       bytea NOT NULL REFERENCES accounts(id),
    envelope      bytea NOT NULL,                                 -- opaque ciphertext (envelope v2 pending)
    envelope_hash bytea NOT NULL,                                 -- SHA3-512
    size          bigint NOT NULL,
    idx           bytea NOT NULL,                                 -- encrypted index entry
    rev           bigint NOT NULL,                                -- account object_rev at the last change
    sealed_by     bytea NOT NULL,                                 -- device
    created_at    bigint NOT NULL,
    updated_at    bigint NOT NULL
);
CREATE INDEX objects_account_rev ON objects (account, rev);

CREATE TABLE object_tombstones (
    id            bytea PRIMARY KEY,
    account       bytea NOT NULL,
    rev           bigint NOT NULL,
    deleted_at    bigint NOT NULL
);
CREATE INDEX tombstones_account_rev ON object_tombstones (account, rev);

CREATE TABLE download_tickets (
    ticket        bytea PRIMARY KEY CHECK (length(ticket) = 32),
    session       bytea NOT NULL,
    object        bytea NOT NULL,
    expires_at    bigint NOT NULL
);

-- The ledger: each account's hash chain; every entry is also a public-log leaf.
CREATE TABLE ledger_entries (
    account       bytea  NOT NULL,
    seq           bigint NOT NULL,
    at            bigint NOT NULL,
    type          text   NOT NULL,
    body          bytea,                                          -- the exact JSON bytes hashed; NULL once redacted (closed > 7 years)
    prev          bytea  NOT NULL,
    hash          bytea  NOT NULL,
    leaf_index    bigint NOT NULL UNIQUE,
    PRIMARY KEY (account, seq)
);

CREATE TABLE tlog_nodes (
    level         integer NOT NULL,
    idx           bigint  NOT NULL,
    hash          bytea   NOT NULL,
    PRIMARY KEY (level, idx)
);

-- one row: the log's size, so appends serialise on it (SELECT … FOR UPDATE)
CREATE TABLE tlog_state (
    one           boolean PRIMARY KEY DEFAULT true CHECK (one),
    size          bigint NOT NULL
);
INSERT INTO tlog_state (size) VALUES (0);

CREATE TABLE tlog_checkpoints (
    size          bigint PRIMARY KEY,
    root          bytea  NOT NULL,
    at            bigint NOT NULL,
    sig           bytea  NOT NULL                                 -- dual (ML-DSA-87 + SLH-DSA)
);

CREATE TABLE tlog_cosigs (
    size          bigint NOT NULL REFERENCES tlog_checkpoints(size) ON DELETE CASCADE,
    name          text   NOT NULL,
    sig           bytea  NOT NULL,
    at            bigint NOT NULL,
    PRIMARY KEY (size, name)
);

-- Device links: a new device asks to join; an existing device approves it for one device key.
CREATE TABLE links (
    code          text   PRIMARY KEY,
    device_vk     bytea  NOT NULL,                               -- the only device key that can join with it
    kem_pk        bytea  NOT NULL,                               -- the new device's one-time key (seed sealed to it)
    platform      text   NOT NULL DEFAULT '',
    status        text   NOT NULL CHECK (status IN ('waiting', 'approved', 'used')),
    account       bytea,
    envelope      bytea,                                          -- the account seed sealed to kem_pk
    created_at    bigint NOT NULL,
    expires_at    bigint NOT NULL,
    used_at       bigint
);

-- Recovery (hardened mode only).
CREATE TABLE recovery_mode (
    account       bytea PRIMARY KEY REFERENCES accounts(id),
    mode          text  NOT NULL CHECK (mode IN ('holder-only', 'hardened')),
    version       integer NOT NULL,
    statement     bytea NOT NULL,                                 -- the account key's signature
    hash          bytea NOT NULL                                  -- what the next statement chains to
);

CREATE TABLE recovery_cards (
    account       bytea PRIMARY KEY REFERENCES accounts(id),
    tag           bytea NOT NULL UNIQUE,                          -- server-keyed (HSM card-tag) lookup tag
    blob          bytea NOT NULL,                                 -- the card part, sealed on the phone
    set_at        bigint NOT NULL
);

CREATE TABLE recovery_witnesses (
    account       bytea NOT NULL REFERENCES accounts(id),
    witness       bytea NOT NULL,                                 -- the witness's account id
    threshold     integer NOT NULL,
    envelope      bytea NOT NULL,                                 -- this witness's piece, sealed to the witness
    set_at        bigint NOT NULL,
    PRIMARY KEY (account, witness)
);
CREATE INDEX witnesses_witness ON recovery_witnesses (witness);

CREATE TABLE recovery_requests (
    id            bytea PRIMARY KEY CHECK (length(id) = 16),      -- a 128-bit capability only the new device knows
    ref           text  NOT NULL UNIQUE,                          -- what alerts show
    code          text  NOT NULL UNIQUE,                          -- what the new device shows its witnesses
    account       bytea,                                          -- bound by the first proof
    device_vk     bytea NOT NULL,                                 -- the device that will join when released
    kem_pk        bytea NOT NULL,                                 -- the new device's key (pieces are sealed to it)
    platform      text  NOT NULL DEFAULT '',
    status        text  NOT NULL CHECK (status IN ('collecting', 'waiting', 'cancelled', 'completed', 'expired')),
    created_at    bigint NOT NULL,
    expires_at    bigint NOT NULL,
    release_at    bigint,
    closed_at     bigint,
    network       text  NOT NULL                                  -- for the per-network cap only
);
CREATE INDEX requests_account ON recovery_requests (account) WHERE status IN ('collecting', 'waiting');

CREATE TABLE recovery_evidence (
    request       bytea NOT NULL REFERENCES recovery_requests(id) ON DELETE CASCADE,
    kind          text  NOT NULL CHECK (kind IN ('card', 'witness', 'anchor', 'key')),
    witness       bytea NOT NULL DEFAULT ''::bytea,               -- '' unless kind = witness
    blob          bytea,                                          -- what the new device gets on release
    at            bigint NOT NULL,
    PRIMARY KEY (request, kind, witness)
);

-- Single-use statements from other units (an anon `spent` statement registers one account).
CREATE TABLE used_statements (
    hash          bytea PRIMARY KEY,
    expires_at    bigint NOT NULL
);

CREATE TABLE duress (
    account       bytea NOT NULL REFERENCES accounts(id),
    at            bigint NOT NULL,
    proof_hash    bytea NOT NULL UNIQUE,
    PRIMARY KEY (account, at, proof_hash)
);
