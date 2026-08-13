import { Box, Divider, Stack, Typography } from "@mui/material"
import { useId, type ReactNode } from "react"

type AccountBoxListProps = {
    /** Group label. Owns an `h2`, so the boxes inside can be `h3`. */
    title: string
    description?: string
    /**
     * Columns from `md` up; always one below that.
     *
     * Lists of devices and providers read better across the full width, so those groups use
     * one column. Short blocks pair up in two.
     */
    columns?: 1 | 2
    children: ReactNode
}

/**
 * A labelled group of account boxes.
 *
 * Layout belongs to the page, not to nine separate box components each carrying its own
 * `flex` value, so this is the only place that decides how boxes are placed — and it names
 * the group while it is at it, which is what turns a wall of equal cards into an outline.
 */
export default function AccountBoxList({
    title,
    description,
    columns = 2,
    children,
}: AccountBoxListProps) {
    const headingId = useId()

    return (
        <Box component="section" aria-labelledby={headingId}>
            <Stack direction="row" sx={{ alignItems: "center", gap: 2 }}>
                <Typography
                    id={headingId}
                    component="h2"
                    variant="overline"
                    sx={{ color: "text.secondary", flexShrink: 0 }}
                >
                    {title}
                </Typography>

                <Divider aria-hidden sx={{ flex: 1 }} />
            </Stack>

            {description && (
                <Typography variant="body2" sx={{ mt: 0.5, color: "text.secondary" }}>
                    {description}
                </Typography>
            )}

            <Box
                sx={{
                    mt: 2,
                    display: "grid",
                    gap: { xs: 2, md: 3 },
                    alignItems: "stretch",
                    gridTemplateColumns: {
                        xs: "1fr",
                        md: columns === 2 ? "repeat(2, minmax(0, 1fr))" : "1fr",
                    },
                }}
            >
                {children}
            </Box>
        </Box>
    )
}
