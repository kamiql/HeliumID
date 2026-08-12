import { Navigate, Outlet, useLocation } from "react-router"
import { useAuthStore } from "../../stores/auth.store.ts"

export default function RequireAuth() {
    const user = useAuthStore((state) => state.user)
    const location = useLocation()

    if (!user) {
        // Remember where they were headed so login can send them back.
        const returnTo = `${location.pathname}${location.search}`
        const query = returnTo && returnTo !== "/" ? `?return_to=${encodeURIComponent(returnTo)}` : ""
        return <Navigate to={`/login${query}`} replace />
    }

    return <Outlet />
}
