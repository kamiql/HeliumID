-- ---------------------------------------------------------------------------
-- WebAuthn credentials: bind the reserved table to its owning MFA factor
-- ---------------------------------------------------------------------------
--
-- `webauthn_credentials` was created empty in V1 and reserved for this milestone. Everything
-- the passkey repository needs is already there — the columns, the unique index on
-- `credential_id`, the lookup index on `user_id`, and `'WEBAUTHN'` in `mfa_factors_type_check`.
-- The one thing V1 could not express is the relationship that makes a passkey a factor rather
-- than a parallel credential store:
--
--     webauthn_credentials.id IS mfa_factors.id
--
-- exactly as `totp_factors.factor_id` is. That identity is what lets a passkey be listed,
-- labelled, activated and revoked through the generic factor endpoints, and it is why the
-- domain type names the column `factorId` while the table keeps calling it `id`.
--
-- This migration is therefore purely additive: one FOREIGN KEY. Deliberately so.
--
--   * No column is added, dropped or retyped, so no existing row is rewritten and the table is
--     not exclusively locked for a rewrite.
--   * No `NOT NULL` is added to an existing column — `id` is already the PRIMARY KEY.
--   * No data migration and no DELETE. The table has never been written to by any released
--     code path, so there is nothing to backfill. If a row somehow exists whose `id` is not a
--     factor, this statement *fails the deployment loudly* and leaves that row untouched. A
--     failed migration with intact data is the outcome we want here; a `DELETE` that quietly
--     discarded a user's registered authenticator is not.
--
-- Forward-only, as Flyway runs with validateOnMigrate(true). The rollback is a single
-- `ALTER TABLE webauthn_credentials DROP CONSTRAINT webauthn_credentials_factor_fk;`, which
-- restores the V1 shape exactly and destroys nothing; the feature itself switches off in code
-- without touching the schema.
--
-- Cascade direction: revoking or deleting the factor removes the credential with it. The
-- inverse must not be possible — an `mfa_factors` row of type WEBAUTHN with no credential
-- behind it would present the user with a second factor that can never be satisfied.

ALTER TABLE webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_factor_fk
        FOREIGN KEY (id) REFERENCES mfa_factors (id) ON DELETE CASCADE;
