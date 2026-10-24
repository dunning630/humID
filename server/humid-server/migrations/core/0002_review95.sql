-- core: fixes from the PR #95 review. 0001 is frozen (applied migrations never change).

-- H-1: a duress session is shown Check-in as it was at its sign-in; its own check-ins move it.
ALTER TABLE sessions ADD COLUMN checkin_view jsonb;

-- H-3: sign-in challenges are stateless (an HSM MAC); only a challenge that signed someone in
-- is recorded, so it can't sign anyone in twice. Nobody can use up another device's challenges.
CREATE TABLE used_challenges (
    hash          bytea  PRIMARY KEY,
    expires_at    bigint NOT NULL
);

-- M-3: a duress sign-in's erase request to keys, written in the sign-in's own transaction and
-- delivered after the reply, with retries, until keys acts on it (or says it already did).
CREATE TABLE duress_pending (
    proof_hash    bytea  PRIMARY KEY,
    account       bytea  NOT NULL,
    proof         jsonb  NOT NULL,                               -- the DuressProof (certificate + sign-in)
    created_at    bigint NOT NULL,
    attempts      integer NOT NULL DEFAULT 0,
    next_at       bigint NOT NULL
);

-- H-1: ledger entries that would tell a duress session what happened (session.duress, a
-- refused open in that session). Appended once no duress session of the account is live.
CREATE TABLE deferred_entries (
    id            bigserial PRIMARY KEY,
    account       bytea  NOT NULL,
    type          text   NOT NULL,
    detail        jsonb  NOT NULL,
    at            bigint NOT NULL,
    proof_hash    bytea                                          -- NULL: asserted by the server
);
CREATE INDEX deferred_account ON deferred_entries (account);

-- L-8: one checkin.erased per erase, however many sweeps it takes.
CREATE TABLE erase_sweeps (
    account       bytea  NOT NULL,
    erased_at     bigint NOT NULL,
    PRIMARY KEY (account, erased_at)
);

-- HumID join requests (humid-core 0x0108) and per-network buckets for links (M-5, L-18).
ALTER TABLE links ADD COLUMN request bytea;                  -- the self-signed join request
ALTER TABLE links ADD COLUMN binding bytea;                  -- H("HUMID-PQ2 join-binding", [body])
ALTER TABLE links ADD COLUMN wants bytea;                    -- the account the request names
ALTER TABLE links ADD COLUMN bucket text NOT NULL DEFAULT '';
CREATE INDEX links_bucket ON links (bucket, expires_at);
CREATE INDEX requests_unbound ON recovery_requests (network, expires_at) WHERE account IS NULL;

-- M-6: live checks per account per day (each buys post tokens).
CREATE TABLE live_check_days (
    account       bytea   NOT NULL,
    day           bigint  NOT NULL,                              -- days since the epoch
    n             integer NOT NULL,
    PRIMARY KEY (account, day)
);

-- M-7: the highest policy this unit accepted, in its replicated database (not only a file).
CREATE TABLE policy_seen (
    one           boolean PRIMARY KEY DEFAULT true CHECK (one),
    version       bigint NOT NULL,
    hash          bytea  NOT NULL
);
