import { Navigate, Outlet } from "react-router"
import { useAuthStore } from "../../stores/auth.store"

export default function RequireAuth() {
    const user = useAuthStore((state) => state.user)

    if (!user) {
        return <Navigate to="/login" replace />
    }

    return <Outlet />
}