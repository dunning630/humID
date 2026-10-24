-- keys: fixes from the PR #95 review. 0001 is frozen.

-- M-7: the highest policy this unit accepted, in its replicated database (not only a file).
CREATE TABLE policy_seen (
    one           boolean PRIMARY KEY DEFAULT true CHECK (one),
    version       bigint NOT NULL,
    hash          bytea  NOT NULL
);
