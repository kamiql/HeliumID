import { DarkMode, LightMode } from "@mui/icons-material";
import { IconButton } from "@mui/material";
import { useTheme } from "../../hooks/useTheme.ts";

export default function ThemeToggle() {
    const { mode, toggleTheme } = useTheme();

    return (
        <IconButton
            onClick={toggleTheme}
            color="primary"
            aria-label="Toggle theme"
        >
            {mode === "dark" ? <LightMode /> : <DarkMode />}
        </IconButton>
    );
}