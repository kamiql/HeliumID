import { useMemo } from "react"
import { useAuthStore } from "../stores/auth.store.ts"

/**
 * The signed-in user's effective permissions.
 *
 * The backend flattens roles into a permission set and ships it on the session payload, so the
 * UI never has to resolve roles itself. This is presentation only — every endpoint re-checks
 * the permission server-side, and hiding a button is not an authorization control.
 */
export function usePermissions() {
    const permissions = useAuthStore((state) => state.user?.permissions)

    return useMemo(() => {
        const granted = new Set(permissions ?? [])

        return {
            all: permissions ?? [],
            has: (permission: string) => granted.has(permission),
            hasAny: (required: string[]) => required.some((item) => granted.has(item)),
            hasAll: (required: string[]) => required.every((item) => granted.has(item)),
        }
    }, [permissions])
}

/** Permission strings from `Permission.kt`, so screens do not hard-code literals. */
export const Permissions = {
    ACCOUNT_PASSWORD_CHANGE: "account:password:change",
    ACCOUNT_EMAIL_CHANGE: "account:email:change",
    ACCOUNT_MFA_MANAGE: "account:mfa:manage",
    ACCOUNT_PROVIDER_MANAGE: "account:provider:manage",
    ACCOUNT_SESSION_MANAGE: "account:session:manage",
    ADMIN_USER_READ: "admin:user:read",
    ADMIN_USER_WRITE: "admin:user:write",
    ADMIN_USER_DELETE: "admin:user:delete",
    ADMIN_ROLE_READ: "admin:role:read",
    ADMIN_ROLE_WRITE: "admin:role:write",
    ADMIN_CLIENT_READ: "admin:client:read",
    ADMIN_CLIENT_WRITE: "admin:client:write",
    ADMIN_AUDIT_READ: "admin:audit:read",
} as const
