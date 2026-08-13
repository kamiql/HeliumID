import { createContext, useContext } from "react"
import type { PaletteMode } from "../lib/theme.ts"

/** What the user chose. `"system"` defers to `prefers-color-scheme`. */
export type ThemeMode = "light" | "dark" | "system"

export type ThemeContextType = {
    /** The stored preference, including `"system"`. */
    mode: ThemeMode
    /** The palette actually in use once `"system"` has been resolved. */
    resolvedMode: PaletteMode
    setMode: (mode: ThemeMode) => void
    /** Flips between light and dark, leaving `"system"` behind. */
    toggleTheme: () => void
}

export const ThemeContext = createContext<ThemeContextType | null>(null)

export function useTheme() {
    const context = useContext(ThemeContext)

    if (!context) {
        throw new Error("useTheme must be used within a ThemeProvider")
    }

    return context
}
