-- Reference data only.
--
-- Deliberately contains no user account, no OAuth client and no secret of any kind. Seeding a
-- default administrator here would put a credential in source control and in every deployment
-- that runs the migration. Dev bootstrap happens at startup, gated on HELIUM_ENV=dev, and logs
-- a warning; production operators create the first administrator through a one-off command.

INSERT INTO roles (name, description, color, built_in, created_at, updated_at)
VALUES ('ADMINISTRATOR', 'Full administrative access to users, clients and audit data.', '#EF4444', true, now(), now()),
       ('USER', 'Standard account self-service.', '#5865F2', true, now(), now());

INSERT INTO role_permissions (role_name, permission)
VALUES ('ADMINISTRATOR', 'account:password:change'),
       ('ADMINISTRATOR', 'account:email:change'),
       ('ADMINISTRATOR', 'account:mfa:manage'),
       ('ADMINISTRATOR', 'account:provider:manage'),
       ('ADMINISTRATOR', 'account:session:manage'),
       ('ADMINISTRATOR', 'admin:user:read'),
       ('ADMINISTRATOR', 'admin:user:write'),
       ('ADMINISTRATOR', 'admin:user:delete'),
       ('ADMINISTRATOR', 'admin:role:read'),
       ('ADMINISTRATOR', 'admin:role:write'),
       ('ADMINISTRATOR', 'admin:client:read'),
       ('ADMINISTRATOR', 'admin:client:write'),
       ('ADMINISTRATOR', 'admin:audit:read'),
       ('USER', 'account:password:change'),
       ('USER', 'account:email:change'),
       ('USER', 'account:mfa:manage'),
       ('USER', 'account:provider:manage'),
       ('USER', 'account:session:manage');

INSERT INTO oauth_scopes (name, description, implicit, created_at)
VALUES ('openid', 'Confirm your identity', true, now()),
       ('profile', 'See your name and username', false, now()),
       ('email', 'See your email address', false, now()),
       ('offline_access', 'Stay signed in when you are not using the app', false, now());
