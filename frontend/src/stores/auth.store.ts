import { create } from "zustand"
import {
    authApi,
    type LoginRequest,
    type RegisterRequest,
} from "../api/auth"
import type { User } from "../api/user"

type AuthState = {
    user: User | null
    initialized: boolean
    loading: boolean
    initialize: () => Promise<void>
    login: (request: LoginRequest) => Promise<void>
    register: (request: RegisterRequest) => Promise<void>
    logout: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
    user: null,
    initialized: false,
    loading: false,

    initialize: async () => {
        set({ loading: true })

        try {
            const response = await authApi.me()

            set({
                user: response.data,
                initialized: true,
                loading: false,
            })
        } catch {
            set({
                user: null,
                initialized: true,
                loading: false,
            })
        }
    },

    login: async (request) => {
        set({ loading: true })

        try {
            await authApi.login(request)

            const response = await authApi.me()

            set({
                user: response.data,
                loading: false,
            })
        } catch (error) {
            set({ loading: false })
            throw error
        }
    },

    register: async (request) => {
        set({ loading: true })

        try {
            await authApi.register(request)

            const response = await authApi.me()

            set({
                user: response.data,
                loading: false,
            })
        } catch (error) {
            set({ loading: false })
            throw error
        }
    },

    logout: async () => {
        set({ loading: true })

        try {
            await authApi.logout()

            set({
                user: null,
                loading: false,
            })
        } catch (error) {
            set({ loading: false })
            throw error
        }
    },
}))