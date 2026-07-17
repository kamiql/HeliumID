import { useAuthStore } from "../stores/auth.store"

export function useUser() {
    const user = useAuthStore((state) => state.user)

    if (!user) {
        throw new Error("useUser must be used within an authenticated context")
    }

    return user
}