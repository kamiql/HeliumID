import { alpha, createTheme, type Theme } from "@mui/material/styles"
import type { Shadows } from "@mui/material/styles"

export type PaletteMode = "light" | "dark"

/** The pixel wordmark. Reserved for the logo — never for prose or headings. */
export const BRAND_FONT = '"Silkscreen", "Inter", sans-serif'

export const UI_FONT = [
    '"Inter"',
    "-apple-system",
    "BlinkMacSystemFont",
    '"Segoe UI"',
    "Roboto",
    '"Helvetica Neue"',
    "Arial",
    "sans-serif",
].join(", ")

/** Identifiers, secrets and tokens: fixed width so a mistyped character is visible. */
export const MONO_FONT = [
    '"JetBrains Mono"',
    "ui-monospace",
    "SFMono-Regular",
    '"SF Mono"',
    "Menlo",
    "Consolas",
    "monospace",
].join(", ")

/** Nav rail width. Exported so the shell and its content can agree on one number. */
export const NAV_WIDTH = 268

/**
 * One elevation ramp for the whole app.
 *
 * MUI's default shadows are tuned for a material paper metaphor and read as heavy on a flat
 * layout, so surfaces get a soft two-part shadow (a tight contact edge plus a wide ambient
 * blur) and most of them use a border instead of any shadow at all.
 */
function buildShadows(mode: PaletteMode): Shadows {
    const key = mode === "dark" ? "0, 0, 0" : "15, 23, 42"
    const strength = mode === "dark" ? 1.9 : 1

    const ramp = Array.from({ length: 25 }, (_, index) => {
        if (index === 0) return "none"

        const step = index / 24
        const y = Math.round(2 + step * 30)
        const blur = Math.round(6 + step * 60)
        const base = 0.05 + step * 0.13

        return [
            `0 1px 2px rgba(${key}, ${(base * 0.6 * strength).toFixed(3)})`,
            `0 ${y}px ${blur}px rgba(${key}, ${(base * strength).toFixed(3)})`,
        ].join(", ")
    })

    return ramp as unknown as Shadows
}

function buildPalette(mode: PaletteMode) {
    if (mode === "dark") {
        return {
            mode,
            primary: {
                main: "#818CF8",
                light: "#A5B4FC",
                dark: "#6366F1",
                contrastText: "#141726",
            },
            secondary: {
                main: "#2DD4BF",
                light: "#5EEAD4",
                dark: "#14B8A6",
                contrastText: "#0A1F1C",
            },
            success: { main: "#4ADE80", light: "#86EFAC", dark: "#22C55E", contrastText: "#052E16" },
            warning: { main: "#FBBF24", light: "#FCD34D", dark: "#F59E0B", contrastText: "#231603" },
            error: { main: "#F87171", light: "#FCA5A5", dark: "#EF4444", contrastText: "#2A0A0A" },
            info: { main: "#38BDF8", light: "#7DD3FC", dark: "#0EA5E9", contrastText: "#04212F" },
            background: { default: "#0B0F1A", paper: "#121826" },
            text: {
                primary: "#E8EDF5",
                secondary: "#9AA8BC",
                disabled: "#64748B",
            },
            divider: "rgba(148, 163, 184, 0.18)",
            action: {
                hover: "rgba(148, 163, 184, 0.08)",
                selected: "rgba(129, 140, 248, 0.16)",
                disabledBackground: "rgba(148, 163, 184, 0.12)",
                disabled: "rgba(232, 237, 245, 0.34)",
                focus: "rgba(129, 140, 248, 0.24)",
            },
        }
    }

    return {
        mode,
        primary: {
            main: "#4F46E5",
            light: "#6366F1",
            dark: "#4338CA",
            contrastText: "#FFFFFF",
        },
        secondary: {
            main: "#0D9488",
            light: "#14B8A6",
            dark: "#0F766E",
            contrastText: "#FFFFFF",
        },
        // Semantic colours are picked for contrast, not vibrancy: each one has to carry white
        // text on a filled chip or button at 4.5:1 or better.
        success: { main: "#15803D", light: "#22C55E", dark: "#166534", contrastText: "#FFFFFF" },
        warning: { main: "#B45309", light: "#F59E0B", dark: "#92400E", contrastText: "#FFFFFF" },
        error: { main: "#DC2626", light: "#EF4444", dark: "#B91C1C", contrastText: "#FFFFFF" },
        info: { main: "#0369A1", light: "#0EA5E9", dark: "#075985", contrastText: "#FFFFFF" },
        background: { default: "#F6F8FB", paper: "#FFFFFF" },
        text: {
            primary: "#0F172A",
            secondary: "#475569",
            disabled: "#94A3B8",
        },
        divider: "#E3E8EF",
        action: {
            hover: "rgba(15, 23, 42, 0.04)",
            selected: "rgba(79, 70, 229, 0.10)",
            disabledBackground: "rgba(15, 23, 42, 0.08)",
            disabled: "rgba(15, 23, 42, 0.32)",
            focus: "rgba(79, 70, 229, 0.16)",
        },
    }
}

/**
 * The application theme.
 *
 * Everything visual is defined here: pages set layout with `sx`, but colours, radii, the type
 * scale and component shapes come from this file so a change lands everywhere at once.
 */
export function createAppTheme(mode: PaletteMode): Theme {
    const base = createTheme({
        palette: buildPalette(mode),
        shape: { borderRadius: 10 },
        shadows: buildShadows(mode),
    })

    const { palette, breakpoints } = base
    const isDark = mode === "dark"

    /** Focus ring used on every interactive surface, so keyboard focus is never ambiguous. */
    const focusRing = {
        outline: `2px solid ${palette.primary.main}`,
        outlineOffset: "2px",
    }

    return createTheme(base, {
        typography: {
            fontFamily: UI_FONT,
            htmlFontSize: 16,
            // Six sizes for the whole app. Anything that needs to look different changes
            // weight or colour, not size.
            h1: { fontSize: "2rem", fontWeight: 700, lineHeight: 1.2, letterSpacing: "-0.02em" },
            h2: {
                fontSize: "1.625rem",
                fontWeight: 700,
                lineHeight: 1.25,
                letterSpacing: "-0.015em",
            },
            h3: { fontSize: "1.375rem", fontWeight: 700, lineHeight: 1.3, letterSpacing: "-0.01em" },
            h4: {
                fontSize: "1.25rem",
                fontWeight: 700,
                lineHeight: 1.3,
                letterSpacing: "-0.01em",
                [breakpoints.up("sm")]: { fontSize: "1.5rem" },
            },
            h5: { fontSize: "1.0625rem", fontWeight: 600, lineHeight: 1.4 },
            h6: { fontSize: "0.9375rem", fontWeight: 600, lineHeight: 1.45 },
            subtitle1: { fontSize: "0.9375rem", fontWeight: 600, lineHeight: 1.5 },
            subtitle2: {
                fontSize: "0.8125rem",
                fontWeight: 600,
                lineHeight: 1.5,
                letterSpacing: "0.01em",
            },
            body1: { fontSize: "0.9375rem", lineHeight: 1.6 },
            body2: { fontSize: "0.875rem", lineHeight: 1.55 },
            caption: { fontSize: "0.75rem", lineHeight: 1.5 },
            overline: {
                fontSize: "0.6875rem",
                fontWeight: 700,
                letterSpacing: "0.08em",
                lineHeight: 1.6,
                textTransform: "uppercase",
            },
            button: {
                fontSize: "0.875rem",
                fontWeight: 600,
                letterSpacing: 0,
                textTransform: "none",
            },
        },

        components: {
            MuiCssBaseline: {
                styleOverrides: {
                    "*, *::before, *::after": { boxSizing: "border-box" },
                    html: { WebkitFontSmoothing: "antialiased", MozOsxFontSmoothing: "grayscale" },
                    body: {
                        minHeight: "100vh",
                        backgroundColor: palette.background.default,
                        // No decorative gradient: a flat ground keeps every surface boundary
                        // meaningful and avoids banding behind the translucent app bar.
                        backgroundImage: "none",
                    },
                    "#root": { minHeight: "100vh" },
                    // A focus ring the user cannot see is the same as none at all, so it is
                    // never removed — only replaced by the component-level rings below.
                    ":focus-visible": focusRing,
                    "::selection": {
                        backgroundColor: alpha(palette.primary.main, isDark ? 0.35 : 0.18),
                    },
                    "@media (prefers-reduced-motion: reduce)": {
                        "*, *::before, *::after": {
                            animationDuration: "0.01ms !important",
                            animationIterationCount: "1 !important",
                            transitionDuration: "0.01ms !important",
                            scrollBehavior: "auto !important",
                        },
                    },
                    "*::-webkit-scrollbar": { width: 10, height: 10 },
                    "*::-webkit-scrollbar-thumb": {
                        borderRadius: 8,
                        border: "2px solid transparent",
                        backgroundClip: "content-box",
                        backgroundColor: alpha(palette.text.primary, 0.18),
                    },
                    "*::-webkit-scrollbar-thumb:hover": {
                        backgroundColor: alpha(palette.text.primary, 0.3),
                    },
                },
            },

            MuiPaper: {
                styleOverrides: {
                    root: { backgroundImage: "none" },
                    outlined: { borderColor: palette.divider },
                },
            },

            MuiCard: {
                defaultProps: { variant: "outlined" },
                styleOverrides: {
                    root: { borderRadius: 14, borderColor: palette.divider },
                },
            },

            MuiCardContent: {
                styleOverrides: {
                    root: {
                        padding: 20,
                        "&:last-child": { paddingBottom: 20 },
                    },
                },
            },

            MuiButton: {
                defaultProps: { disableElevation: true },
                styleOverrides: {
                    root: {
                        borderRadius: 8,
                        // 40px medium / 34px small: consistent so button rows never look
                        // ragged, and large enough to hit reliably on a touch screen.
                        minHeight: 40,
                        paddingInline: 16,
                        "&.Mui-focusVisible": focusRing,
                    },
                    sizeSmall: { minHeight: 34, paddingInline: 12, fontSize: "0.8125rem" },
                    sizeLarge: { minHeight: 48, paddingInline: 22, fontSize: "0.9375rem" },
                    outlined: { borderColor: alpha(palette.text.primary, isDark ? 0.22 : 0.18) },
                    text: { paddingInline: 12 },
                },
            },

            MuiIconButton: {
                styleOverrides: {
                    root: {
                        borderRadius: 8,
                        "&.Mui-focusVisible": focusRing,
                    },
                },
            },

            MuiToggleButton: {
                styleOverrides: {
                    root: {
                        textTransform: "none",
                        fontWeight: 600,
                        borderColor: palette.divider,
                        "&.Mui-focusVisible": focusRing,
                        "&.Mui-selected": {
                            backgroundColor: alpha(palette.primary.main, isDark ? 0.2 : 0.1),
                            color: isDark ? palette.primary.light : palette.primary.dark,
                            "&:hover": {
                                backgroundColor: alpha(palette.primary.main, isDark ? 0.28 : 0.16),
                            },
                        },
                    },
                },
            },

            MuiTextField: { defaultProps: { variant: "outlined" } },

            MuiOutlinedInput: {
                styleOverrides: {
                    root: {
                        borderRadius: 8,
                        backgroundColor: isDark ? alpha("#0B0F1A", 0.4) : palette.background.paper,
                        "& .MuiOutlinedInput-notchedOutline": { borderColor: palette.divider },
                        "&:hover .MuiOutlinedInput-notchedOutline": {
                            borderColor: alpha(palette.text.primary, 0.32),
                        },
                        "&.Mui-focused .MuiOutlinedInput-notchedOutline": { borderWidth: 2 },
                        "&.Mui-disabled": { backgroundColor: alpha(palette.text.primary, 0.03) },
                    },
                    input: { "&::placeholder": { opacity: isDark ? 0.55 : 0.65 } },
                },
            },

            MuiFormLabel: {
                styleOverrides: {
                    // The asterisk is never the only signal that a field is required, but it
                    // should at least be legible where it is used.
                    asterisk: { color: palette.error.main },
                },
            },

            MuiFormHelperText: {
                styleOverrides: {
                    root: { marginLeft: 2, marginRight: 0, fontSize: "0.75rem", lineHeight: 1.5 },
                },
            },

            MuiFormControlLabel: {
                styleOverrides: {
                    label: { fontSize: "0.875rem" },
                },
            },

            MuiInputLabel: { styleOverrides: { root: { fontSize: "0.9375rem" } } },

            MuiAlert: {
                defaultProps: { variant: "standard" },
                styleOverrides: {
                    root: { borderRadius: 10, alignItems: "flex-start", fontSize: "0.875rem" },
                    icon: { paddingTop: 9 },
                    message: { paddingBlock: 7, minWidth: 0 },
                    action: { paddingTop: 4 },
                },
            },

            MuiAlertTitle: { styleOverrides: { root: { fontWeight: 600, marginBottom: 2 } } },

            MuiChip: {
                styleOverrides: {
                    root: { borderRadius: 7, fontWeight: 500 },
                    sizeSmall: { height: 22, fontSize: "0.75rem" },
                    label: { paddingInline: 9 },
                    outlined: { borderColor: alpha(palette.text.primary, 0.2) },
                },
            },

            MuiDialog: {
                defaultProps: { fullWidth: true, maxWidth: "sm" },
                styleOverrides: {
                    paper: {
                        borderRadius: 16,
                        // Full-bleed sheet below sm: a 16px-inset dialog on a 360px screen
                        // leaves too little room for form fields.
                        [breakpoints.down("sm")]: {
                            margin: 0,
                            width: "100%",
                            maxWidth: "100%",
                            maxHeight: "100%",
                            borderRadius: 0,
                        },
                    },
                },
            },

            MuiDialogTitle: {
                styleOverrides: {
                    root: { fontSize: "1.0625rem", fontWeight: 700, padding: "20px 24px 8px" },
                },
            },

            MuiDialogContent: { styleOverrides: { root: { padding: "8px 24px 20px" } } },

            MuiDialogActions: {
                styleOverrides: {
                    root: {
                        padding: "12px 20px 20px",
                        gap: 8,
                        "& > :not(style) ~ :not(style)": { marginLeft: 0 },
                    },
                },
            },

            MuiDialogContentText: { styleOverrides: { root: { color: palette.text.secondary } } },

            MuiAppBar: {
                defaultProps: { elevation: 0, color: "inherit" },
                styleOverrides: {
                    root: {
                        backgroundColor: alpha(palette.background.default, 0.85),
                        backdropFilter: "blur(10px)",
                        color: palette.text.primary,
                        borderBottom: `1px solid ${palette.divider}`,
                        backgroundImage: "none",
                    },
                },
            },

            MuiDrawer: {
                styleOverrides: {
                    paper: {
                        backgroundImage: "none",
                        borderColor: palette.divider,
                    },
                },
            },

            MuiListItemButton: {
                styleOverrides: {
                    root: {
                        borderRadius: 8,
                        minHeight: 42,
                        "&.Mui-focusVisible": focusRing,
                        "&.Mui-selected": {
                            backgroundColor: alpha(palette.primary.main, isDark ? 0.18 : 0.1),
                            color: isDark ? palette.primary.light : palette.primary.dark,
                            "& .MuiListItemIcon-root": { color: "inherit" },
                            "&:hover": {
                                backgroundColor: alpha(palette.primary.main, isDark ? 0.24 : 0.14),
                            },
                        },
                    },
                },
            },

            MuiListItemIcon: {
                styleOverrides: { root: { minWidth: 36, color: palette.text.secondary } },
            },

            MuiListItemText: {
                styleOverrides: {
                    primary: { fontSize: "0.875rem", fontWeight: 500 },
                    secondary: { fontSize: "0.75rem" },
                },
            },

            MuiMenu: {
                styleOverrides: {
                    paper: {
                        borderRadius: 12,
                        border: `1px solid ${palette.divider}`,
                        marginTop: 6,
                        minWidth: 180,
                    },
                    list: { padding: 6 },
                },
            },

            MuiMenuItem: {
                styleOverrides: {
                    root: {
                        borderRadius: 7,
                        minHeight: 38,
                        fontSize: "0.875rem",
                        "&.Mui-focusVisible": focusRing,
                    },
                },
            },

            MuiTableCell: {
                styleOverrides: {
                    root: {
                        borderColor: palette.divider,
                        fontSize: "0.875rem",
                        paddingBlock: 12,
                    },
                    head: {
                        fontSize: "0.75rem",
                        fontWeight: 700,
                        letterSpacing: "0.04em",
                        textTransform: "uppercase",
                        color: palette.text.secondary,
                        backgroundColor: isDark
                            ? alpha("#0B0F1A", 0.6)
                            : alpha(palette.text.primary, 0.02),
                        whiteSpace: "nowrap",
                    },
                },
            },

            MuiTableRow: {
                styleOverrides: {
                    root: {
                        "&:last-of-type .MuiTableCell-body": { borderBottom: "none" },
                        "&.Mui-focusVisible": focusRing,
                    },
                },
            },

            MuiTablePagination: {
                styleOverrides: {
                    root: { borderTop: `1px solid ${palette.divider}` },
                    toolbar: { minHeight: 56, paddingInline: 12 },
                    selectLabel: { fontSize: "0.8125rem" },
                    displayedRows: { fontSize: "0.8125rem" },
                },
            },

            MuiTabs: {
                styleOverrides: {
                    root: { minHeight: 44 },
                    indicator: { height: 2.5, borderRadius: 2 },
                },
            },

            MuiTab: {
                styleOverrides: {
                    root: {
                        textTransform: "none",
                        fontWeight: 600,
                        fontSize: "0.875rem",
                        minHeight: 44,
                        "&.Mui-focusVisible": focusRing,
                    },
                },
            },

            MuiTooltip: {
                defaultProps: { arrow: true },
                styleOverrides: {
                    tooltip: {
                        fontSize: "0.75rem",
                        borderRadius: 7,
                        paddingBlock: 6,
                        paddingInline: 10,
                    },
                },
            },

            MuiLink: {
                defaultProps: { underline: "hover" },
                styleOverrides: {
                    root: {
                        fontWeight: 500,
                        borderRadius: 3,
                        "&.Mui-focusVisible, &:focus-visible": focusRing,
                    },
                },
            },

            MuiDivider: { styleOverrides: { root: { borderColor: palette.divider } } },

            MuiAvatar: { styleOverrides: { root: { fontWeight: 600, fontSize: "0.875rem" } } },

            MuiSkeleton: { defaultProps: { animation: "wave" } },

            MuiCheckbox: { styleOverrides: { root: { "&.Mui-focusVisible": focusRing } } },
            MuiRadio: { styleOverrides: { root: { "&.Mui-focusVisible": focusRing } } },
            MuiSwitch: { styleOverrides: { switchBase: { "&.Mui-focusVisible": focusRing } } },

            MuiBackdrop: {
                styleOverrides: {
                    root: { backgroundColor: alpha("#040711", isDark ? 0.72 : 0.5) },
                },
            },

            MuiBreadcrumbs: {
                styleOverrides: {
                    root: { fontSize: "0.8125rem" },
                    separator: { marginInline: 6, color: palette.text.disabled },
                },
            },

            MuiAccordion: {
                defaultProps: { disableGutters: true, elevation: 0 },
                styleOverrides: {
                    root: {
                        border: `1px solid ${palette.divider}`,
                        borderRadius: 10,
                        "&::before": { display: "none" },
                        "& + &": { marginTop: 8 },
                    },
                },
            },

            MuiAccordionSummary: {
                styleOverrides: {
                    root: {
                        minHeight: 52,
                        "&.Mui-focusVisible": { ...focusRing, backgroundColor: "transparent" },
                    },
                    content: { marginBlock: 12 },
                },
            },
        },
    })
}
