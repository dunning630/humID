-- anon: fixes from the PR #95 review. 0001 is frozen.

-- M-6: the relay's total bytes, kept in SQL (one row, updated in each deposit's transaction),
-- so concurrent deposits can't overshoot the cap and more than one anon process can share it.
CREATE TABLE relay_usage (
    one           boolean PRIMARY KEY DEFAULT true CHECK (one),
    bytes         bigint NOT NULL
);
INSERT INTO relay_usage (bytes) SELECT COALESCE(sum(size), 0)::bigint FROM relay_objects;

-- M-7: the highest policy this unit accepted, in its replicated database (not only a file).
CREATE TABLE policy_seen (
    one           boolean PRIMARY KEY DEFAULT true CHECK (one),
    version       bigint NOT NULL,
    hash          bytea  NOT NULL
);
