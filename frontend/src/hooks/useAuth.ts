import { useShallow } from "zustand/shallow"
import { useAuthStore } from "../stores/auth.store"

export function useAuth() {
    return useAuthStore(
        useShallow((state) => ({
            initialized: state.initialized,
            loading: state.loading,
            login: state.login,
            completeLogin: state.completeLogin,
            register: state.register,
            logout: state.logout,
        }))
    )
}