import { Navigate, Outlet } from "react-router"
import { useAuthStore } from "../../stores/auth.store"

export default function RequireGuest() {
    const user = useAuthStore((state) => state.user)

    if (user) {
        return <Navigate to="/" replace />
    }

    return <Outlet />
}