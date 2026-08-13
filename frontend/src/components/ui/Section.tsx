import { Box, Divider, Paper, Stack, Typography } from "@mui/material"
import type { SxProps, Theme } from "@mui/material/styles"
import type { ElementType, ReactNode } from "react"

export type SectionProps = {
    title: string
    /** One sentence on what this area is for. Optional — omit rather than pad it out. */
    description?: string
    /** Rendered top-right on wide screens, below the description on narrow ones. */
    actions?: ReactNode
    /** Sits between the heading and the body, e.g. a status chip or a blocking notice. */
    banner?: ReactNode
    /** Heading level, so the page keeps a correct h1 → h2 → h3 outline. */
    headingLevel?: "h2" | "h3" | "h4"
    /** Draws attention without colouring the whole surface. */
    tone?: "default" | "danger"
    /** Hides the rule between heading and body for very short sections. */
    disableDivider?: boolean
    /** Removes the body padding, e.g. when the body is a full-bleed table. */
    disableBodyPadding?: boolean
    sx?: SxProps<Theme>
    children?: ReactNode
}

/**
 * The single surface primitive.
 *
 * Every grouped block in the app — account settings, admin panels, table shells — is a
 * `Section`, so heading size, padding, divider and action placement are decided once instead
 * of being re-invented per page.
 */
export default function Section({
    title,
    description,
    actions,
    banner,
    headingLevel = "h2",
    tone = "default",
    disableDivider = false,
    disableBodyPadding = false,
    sx,
    children,
}: SectionProps) {
    return (
        <Paper
            component="section"
            variant="outlined"
            sx={{
                display: "flex",
                flexDirection: "column",
                borderRadius: 3.5,
                overflow: "hidden",
                height: "100%",
                ...(tone === "danger" && {
                    borderColor: "error.main",
                }),
                ...sx,
            }}
        >
            <Box sx={{ px: { xs: 2, sm: 2.5 }, pt: { xs: 2, sm: 2.5 }, pb: 2 }}>
                <Stack
                    direction={{ xs: "column", sm: "row" }}
                    sx={{
                        gap: 1.5,
                        alignItems: { sm: "flex-start" },
                        justifyContent: "space-between",
                    }}
                >
                    <Box sx={{ minWidth: 0 }}>
                        <Typography
                            variant="h5"
                            component={headingLevel as ElementType}
                            sx={{ color: tone === "danger" ? "error.main" : "text.primary" }}
                        >
                            {title}
                        </Typography>

                        {description && (
                            <Typography variant="body2" sx={{ mt: 0.5, color: "text.secondary" }}>
                                {description}
                            </Typography>
                        )}
                    </Box>

                    {actions && (
                        <Stack
                            direction="row"
                            sx={{ gap: 1, flexWrap: "wrap", flexShrink: 0 }}
                        >
                            {actions}
                        </Stack>
                    )}
                </Stack>

                {banner && <Box sx={{ mt: 2 }}>{banner}</Box>}
            </Box>

            {!disableDivider && <Divider />}

            {children !== undefined && (
                <Box
                    sx={{
                        flex: 1,
                        minWidth: 0,
                        ...(disableBodyPadding
                            ? {}
                            : { px: { xs: 2, sm: 2.5 }, py: { xs: 2, sm: 2.5 } }),
                    }}
                >
                    {children}
                </Box>
            )}
        </Paper>
    )
}
