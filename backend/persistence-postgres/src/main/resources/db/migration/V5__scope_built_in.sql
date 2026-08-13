-- Marks the scopes that the server itself depends on.
--
-- Until now the scope catalogue was effectively frozen: `GET /v1/admin/scopes` was the only
-- endpoint, so whatever V2 seeded was all a deployment would ever have. Adding write endpoints
-- means an administrator can now delete a scope, and two of them are load-bearing — `openid`
-- gates ID-token issuance and access to /userinfo. Deleting it would quietly turn OIDC off and
-- surface much later as clients failing to get an id_token.
--
-- Same mechanism as `roles.built_in`, and for the same reason: code depends on these names, so
-- the write path refuses to touch a row flagged here.
--
-- Rollback is `ALTER TABLE oauth_scopes DROP COLUMN built_in;` — no data is lost, since the flag
-- is derived entirely from the four names below.

ALTER TABLE oauth_scopes
    ADD COLUMN built_in boolean NOT NULL DEFAULT false;

-- The four scopes V2__reference_data.sql seeds. Named explicitly rather than "everything that
-- exists right now": a deployment that already added its own scopes by hand must not have them
-- silently promoted to undeletable.
UPDATE oauth_scopes
SET built_in = true
WHERE name IN ('openid', 'profile', 'email', 'offline_access');
