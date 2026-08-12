import { useShallow } from "zustand/shallow"
import { useAuthStore } from "../stores/auth.store.ts"

export function useAuth() {
    return useAuthStore(
        useShallow((state) => ({
            user: state.user,
            initialized: state.initialized,
            loading: state.loading,
            login: state.login,
            completeMfa: state.completeMfa,
            register: state.register,
            logout: state.logout,
            refresh: state.refresh,
            bootstrap: state.bootstrap,
        })),
    )
}
