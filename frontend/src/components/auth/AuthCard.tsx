import { Box, Paper, Typography } from "@mui/material"
import { alpha, type SxProps, type Theme } from "@mui/material/styles"
import type { ReactNode } from "react"
import Brand from "../global/Brand.tsx"

type AuthCardProps = {
    /** The page's only `h1`. */
    title: string
    /** One line under the title explaining what this screen wants. */
    subtitle?: ReactNode
    /**
     * A status mark above the title.
     *
     * Reserved for screens whose whole message is an outcome — "Check your inbox",
     * "Password set", "Email verified". A form does not need one: its fields are the content.
     */
    statusIcon?: ReactNode
    statusTone?: "primary" | "success"
    /** Cross-links rendered below the card, outside the form. */
    footer?: ReactNode
    sx?: SxProps<Theme>
    children?: ReactNode
}

/** The signed-out card shell: wordmark, `h1`, optional subtitle, then the form. */
export default function AuthCard({
    title,
    subtitle,
    statusIcon,
    statusTone = "primary",
    footer,
    sx,
    children,
}: AuthCardProps) {
    return (
        <Box
            sx={{
                width: "100%",
                display: "flex",
                justifyContent: "center",
                // The card keeps its readable width on a 360px phone by giving up the outer
                // gutter rather than the padding that makes the fields comfortable.
                px: { xs: 1.5, sm: 2 },
                ...sx,
            }}
        >
            <Box sx={{ width: "100%", maxWidth: 420, minWidth: 0 }}>
                <Box sx={{ display: "flex", justifyContent: "center", mb: 3 }}>
                    <Brand to="/" />
                </Box>

                <Paper
                    variant="outlined"
                    sx={{
                        p: { xs: 2.5, sm: 4 },
                        borderRadius: 3.5,
                        backgroundColor: "background.paper",
                    }}
                >
                    <Box sx={{ textAlign: "center", mb: 3 }}>
                        {statusIcon && (
                            <Box
                                aria-hidden
                                sx={{
                                    width: 48,
                                    height: 48,
                                    mx: "auto",
                                    mb: 2,
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                    borderRadius: 2.5,
                                    color: `${statusTone}.main`,
                                    backgroundColor: (theme) =>
                                        alpha(theme.palette[statusTone].main, 0.12),
                                }}
                            >
                                {statusIcon}
                            </Box>
                        )}

                        <Typography component="h1" variant="h4">
                            {title}
                        </Typography>

                        {subtitle && (
                            <Typography variant="body2" sx={{ mt: 1, color: "text.secondary" }}>
                                {subtitle}
                            </Typography>
                        )}
                    </Box>

                    {children}
                </Paper>

                {footer && (
                    <Box sx={{ mt: 3, textAlign: "center" }}>{footer}</Box>
                )}
            </Box>
        </Box>
    )
}
