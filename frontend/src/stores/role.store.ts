import { create } from "zustand"
import { api } from "../api/axios.ts"
import type { Role } from "../api/user.ts"

type RoleState = {
    roles: Role[]
    loading: boolean
    initialized: boolean
    initialize: () => Promise<void>
}

export const useRoleStore = create<RoleState>((set, get) => ({
    roles: [],
    loading: false,
    initialized: false,

    initialize: async () => {
        if (get().initialized || get().loading) return

        set({ loading: true })

        try {
            const { data } = await api.get<Role[]>("/data/roles")

            set({
                roles: data,
                initialized: true,
            })
        } finally {
            set({ loading: false })
        }
    },
}))