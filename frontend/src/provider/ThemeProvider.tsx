import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react"
import { ThemeProvider as MuiThemeProvider } from "@mui/material/styles"
import { CssBaseline } from "@mui/material"
import { createAppTheme, type PaletteMode } from "../lib/theme.ts"
import { ThemeContext, type ThemeMode } from "../hooks/useTheme.ts"

const STORAGE_KEY = "theme"
const DARK_QUERY = "(prefers-color-scheme: dark)"

function readStoredMode(): ThemeMode {
    try {
        const stored = localStorage.getItem(STORAGE_KEY)
        if (stored === "light" || stored === "dark" || stored === "system") return stored
    } catch {
        // Private mode or blocked storage: fall through to the system preference.
    }
    return "system"
}

function systemMode(): PaletteMode {
    return typeof window !== "undefined" && window.matchMedia(DARK_QUERY).matches ? "dark" : "light"
}

/**
 * Owns the palette mode for the whole app.
 *
 * The default follows the operating system; an explicit choice is stored and wins from then
 * on. The inline script in `index.html` resolves the same order before first paint so a dark
 * reload does not flash a white page.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
    const [mode, setModeState] = useState<ThemeMode>(readStoredMode)
    const [system, setSystem] = useState<PaletteMode>(systemMode)

    // Track the OS preference for as long as the user is on "system".
    useEffect(() => {
        const query = window.matchMedia(DARK_QUERY)
        const handle = (event: MediaQueryListEvent) => setSystem(event.matches ? "dark" : "light")
        query.addEventListener("change", handle)
        return () => query.removeEventListener("change", handle)
    }, [])

    const resolvedMode: PaletteMode = mode === "system" ? system : mode

    // Tells the browser which palette to use for form controls, scrollbars and the like.
    useEffect(() => {
        document.documentElement.style.colorScheme = resolvedMode
    }, [resolvedMode])

    const setMode = useCallback((next: ThemeMode) => {
        document.documentElement.classList.add("theme-transition")

        setModeState(next)
        try {
            localStorage.setItem(STORAGE_KEY, next)
        } catch {
            // Preference is session-only when storage is unavailable.
        }

        window.setTimeout(() => {
            document.documentElement.classList.remove("theme-transition")
        }, 260)
    }, [])

    const toggleTheme = useCallback(
        () => setMode(resolvedMode === "dark" ? "light" : "dark"),
        [resolvedMode, setMode],
    )

    const theme = useMemo(() => createAppTheme(resolvedMode), [resolvedMode])

    const value = useMemo(
        () => ({ mode, resolvedMode, setMode, toggleTheme }),
        [mode, resolvedMode, setMode, toggleTheme],
    )

    return (
        <ThemeContext.Provider value={value}>
            <MuiThemeProvider theme={theme}>
                <CssBaseline />
                {children}
            </MuiThemeProvider>
        </ThemeContext.Provider>
    )
}
