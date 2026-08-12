import { create } from "zustand"

export type NoticeSeverity = "success" | "info" | "warning" | "error"

export type Notice = {
    id: number
    message: string
    severity: NoticeSeverity
}

type NoticeState = {
    notices: Notice[]
    push: (message: string, severity?: NoticeSeverity) => void
    dismiss: (id: number) => void
}

let nextId = 1

/** A tiny toast queue, used for confirmations and for the global error reactions. */
export const useNoticeStore = create<NoticeState>((set) => ({
    notices: [],

    push: (message, severity = "info") =>
        set((state) => {
            // Collapse duplicates: a burst of identical failures should not stack five toasts.
            if (state.notices.some((notice) => notice.message === message)) return state
            return { notices: [...state.notices, { id: nextId++, message, severity }] }
        }),

    dismiss: (id) =>
        set((state) => ({ notices: state.notices.filter((notice) => notice.id !== id) })),
}))

export function notify(message: string, severity: NoticeSeverity = "info"): void {
    useNoticeStore.getState().push(message, severity)
}
