import { useMemo, useState } from "react";
import { ThemeProvider as MuiThemeProvider } from "@mui/material/styles";
import { CssBaseline } from "@mui/material";
import { createAppTheme } from "../lib/theme.ts";
import { ThemeContext, type ThemeMode } from "../hooks/useTheme.ts";

export function ThemeProvider({ children }: { children: React.ReactNode }) {
    const [mode, setMode] = useState<ThemeMode>(
        () => (localStorage.getItem("theme") as ThemeMode) || "dark"
    );

    const toggleTheme = () => {
        document.documentElement.classList.add("theme-transition");

        setMode((current) => {
            const next = current === "dark" ? "light" : "dark";
            localStorage.setItem("theme", next);
            return next;
        });

        window.setTimeout(() => {
            document.documentElement.classList.remove("theme-transition");
        }, 750);
    };

    const value = useMemo(
        () => ({
            mode,
            toggleTheme,
        }),
        [mode]
    );

    return (
        <ThemeContext.Provider value={value}>
            <MuiThemeProvider theme={createAppTheme(mode)}>
                <CssBaseline />
                {children}
            </MuiThemeProvider>
        </ThemeContext.Provider>
    );
}