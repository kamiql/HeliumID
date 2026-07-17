import { useEffect, type ReactNode } from "react"
import { useAuthStore } from "../../stores/auth.store"

export default function AuthProvider({ children }: { children: ReactNode }) {
    const initialized = useAuthStore((state) => state.initialized)
    const initialize = useAuthStore((state) => state.initialize)

    useEffect(() => {
        initialize()
    }, [initialize])

    if (!initialized) {
        return null
    }

    return children
}