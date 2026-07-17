import { create } from "zustand"

type RequestState = {
    activeRequests: number
    startRequest: () => void
    finishRequest: () => void
}

export const useRequestStore = create<RequestState>((set) => ({
    activeRequests: 0,

    startRequest: () => {
        set((state) => ({
            activeRequests: state.activeRequests + 1,
        }))
    },

    finishRequest: () => {
        set((state) => ({
            activeRequests: Math.max(0, state.activeRequests - 1),
        }))
    },
}))