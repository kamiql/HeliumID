import { Box, Typography } from "@mui/material"
import type { SxProps, Theme } from "@mui/material/styles"
import { Link } from "react-router"
import { BRAND_FONT } from "../../lib/theme.ts"

type BrandProps = {
    /** Wraps the mark in a link. Omit inside a heading that is already the page title. */
    to?: string
    size?: "small" | "medium"
    sx?: SxProps<Theme>
}

/**
 * The HeliumID wordmark.
 *
 * Silkscreen appears here and nowhere else: it is a logotype, and a pixel face set at body
 * or heading size costs more legibility than the character it adds.
 */
export default function Brand({ to, size = "medium", sx }: BrandProps) {
    const content = (
        <>
            <Box
                aria-hidden
                sx={{
                    width: size === "small" ? 22 : 26,
                    height: size === "small" ? 22 : 26,
                    borderRadius: 1.5,
                    flexShrink: 0,
                    background: (theme) =>
                        `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.primary.dark})`,
                }}
            />

            <Typography
                component="span"
                sx={{
                    fontFamily: BRAND_FONT,
                    fontSize: size === "small" ? "0.9375rem" : "1.0625rem",
                    lineHeight: 1,
                    letterSpacing: "0.01em",
                    color: "text.primary",
                }}
            >
                HeliumID
            </Typography>
        </>
    )

    const layout: SxProps<Theme> = {
        display: "inline-flex",
        alignItems: "center",
        gap: 1.25,
        textDecoration: "none",
        borderRadius: 1,
        ...sx,
    }

    if (!to) {
        return <Box sx={layout}>{content}</Box>
    }

    return (
        <Box component={Link} to={to} aria-label="HeliumID — home" sx={layout}>
            {content}
        </Box>
    )
}
