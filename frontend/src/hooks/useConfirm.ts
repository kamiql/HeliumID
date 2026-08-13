import { createContext, useContext } from "react"
import type { ConfirmOptions } from "../provider/ConfirmProvider.tsx"

type ConfirmContextType = {
    /**
     * Raises the shared confirmation prompt and resolves to the user's answer.
     *
     * Options: `message` (required), `title`, `confirmText`, `cancelText`, and `tone`.
     * `tone` defaults to `"danger"` — a red confirm button, a warning icon and focus on
     * Cancel. Pass `tone: "default"` for an action that is deliberate but not destructive
     * (signing out, for example), which renders a neutral primary button and focuses it.
     */
    confirm: (options: ConfirmOptions) => Promise<boolean>
}

export const ConfirmContext = createContext<ConfirmContextType | null>(null)

export function useConfirm() {
    const context = useContext(ConfirmContext)

    if (!context) {
        throw new Error("useConfirm must be used within ConfirmProvider")
    }

    return context
}
