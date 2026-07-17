import { createTheme } from "@mui/material/styles";

export const createAppTheme = (mode: "light" | "dark") =>
    createTheme({
        palette: {
            mode,
            primary: {
                main: "#5865F2",
                light: "#7983F5",
                dark: "#4752C4",
                contrastText: "#ffffff",
            },
            secondary: {
                main: "#3B82F6",
                light: "#60A5FA",
                dark: "#2563EB",
                contrastText: "#ffffff",
            },
            ...(mode === "dark"
                ? {
                    background: {
                        default: "#0B0F19",
                        paper: "#111827",
                    },
                    text: {
                        primary: "#F8FAFC",
                        secondary: "#94A3B8",
                    },
                    divider: "#1E293B",
                }
                : {
                    background: {
                        default: "#F8FAFC",
                        paper: "#FFFFFF",
                    },
                    text: {
                        primary: "#0F172A",
                        secondary: "#64748B",
                    },
                    divider: "#E2E8F0",
                }),
            success: {
                main: "#22C55E",
            },
            error: {
                main: "#EF4444",
            },
            warning: {
                main: "#F59E0B",
            },
            info: {
                main: "#38BDF8",
            },
        },
        components: {
            MuiCssBaseline: {
                styleOverrides: {
                    body: {
                        minHeight: "100vh",
                        background:
                            mode === "dark"
                                ? `
                                    radial-gradient(circle at 20% 20%, rgba(88, 101, 242, 0.2), transparent 35%),
                                    radial-gradient(circle at 80% 80%, rgba(59, 130, 246, 0.25), transparent 35%),
                                    #0B0F19
                                `
                                : `
                                    radial-gradient(circle at 20% 20%, rgba(88, 101, 242, 0.12), transparent 35%),
                                    radial-gradient(circle at 80% 80%, rgba(59, 130, 246, 0.1), transparent 35%),
                                    #F8FAFC
                                `,
                        backgroundAttachment: "fixed",
                    },
                },
            },
            MuiPaper: {
                styleOverrides: {
                    root: {
                        backgroundImage: "none",
                    },
                },
            },
        },
    });