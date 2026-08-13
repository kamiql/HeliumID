-- ---------------------------------------------------------------------------
-- Trusted devices
-- ---------------------------------------------------------------------------
--
-- A device on which the user has completed MFA may skip the challenge on subsequent password
-- logins until `expires_at`. Additive and forward-only: nothing here rewrites an existing table,
-- so the rollback is `DROP TABLE trusted_devices` and the feature switches off by setting
-- HELIUM_TRUSTED_DEVICE_DAYS=0 without touching the schema.
--
-- The security properties live in the column choices:
--
--   * `token_hash` is an HMAC of the cookie value, never the value itself, so a dump of this
--     table is not a list of devices an attacker can impersonate — the same treatment sessions,
--     refresh tokens and verification tokens get;
--   * every lookup is keyed on `(user_id, hash)`, so a token minted for one account cannot be
--     substituted into another;
--   * `previous_token_hash` retains exactly one superseded generation, which is what makes a
--     copied cookie detectable rather than merely expirable;
--   * `expires_at` is absolute and is never extended by use.

CREATE TABLE trusted_devices
(
    id                  uuid PRIMARY KEY,
    user_id             uuid         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- HMAC of the cookie value. A dump of this table yields no usable device.
    token_hash          varchar(128) NOT NULL,
    -- The generation this row just rotated away from, kept solely so that presenting it again
    -- can be recognised as a replay.
    --
    -- It survives an ordinary revocation on purpose: a cookie copied before the owner changed
    -- their password is still worth catching afterwards, and clearing it would make detection
    -- depend on which of the two parties logged in first. It is cleared only when the row is
    -- revoked *for* REUSE_DETECTED, where the theft is already reported and keeping the value
    -- indexed would let the thief trigger a notification on every retry.
    previous_token_hash varchar(128),
    -- Derived from the user agent for the account UI. Informative only — no security decision
    -- reads it, because the user agent is attacker-supplied.
    label               varchar(128),
    created_at          timestamptz  NOT NULL,
    last_used_at        timestamptz  NOT NULL,
    expires_at          timestamptz  NOT NULL,
    revoked_at          timestamptz,
    revoked_reason      varchar(32),

    CONSTRAINT trusted_devices_reason_check CHECK (revoked_reason IN
                                                   ('USER_REVOKED', 'PASSWORD_CHANGED', 'PASSWORD_RESET',
                                                    'MFA_CHANGED', 'ADMIN_ACTION', 'ACCOUNT_DELETED',
                                                    'REUSE_DETECTED')),
    -- A revoked row must say why, and a live row must not pretend it was revoked.
    CONSTRAINT trusted_devices_revocation_check CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

-- Unique: rotation must not be able to produce two rows claiming the same live token.
CREATE UNIQUE INDEX trusted_devices_hash_key ON trusted_devices (token_hash);
CREATE INDEX trusted_devices_prev_hash_idx ON trusted_devices (previous_token_hash)
    WHERE previous_token_hash IS NOT NULL;
CREATE INDEX trusted_devices_user_idx ON trusted_devices (user_id, revoked_at);
CREATE INDEX trusted_devices_expires_idx ON trusted_devices (expires_at);
