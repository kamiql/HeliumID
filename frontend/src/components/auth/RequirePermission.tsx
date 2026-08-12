import { Navigate, Outlet } from "react-router"
import { usePermissions } from "../../hooks/usePermissions.ts"

/**
 * Route guard on the effective permission set from the session payload.
 *
 * This only removes routes from the UI. Every endpoint behind them re-checks the same
 * permission server-side, so bypassing this guard buys an attacker nothing.
 */
export default function RequirePermission({
    require,
    all = false,
}: {
    require: string[]
    all?: boolean
}) {
    const permissions = usePermissions()

    const allowed = all ? permissions.hasAll(require) : permissions.hasAny(require)

    if (!allowed) {
        return <Navigate to="/" replace />
    }

    return <Outlet />
}
