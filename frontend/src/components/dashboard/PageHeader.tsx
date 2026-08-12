import { Box, Stack, Typography } from "@mui/material"
import type { ReactNode } from "react"

type PageHeaderProps = {
    title: string
    description?: string
    actions?: ReactNode
}

/** The dashboard page heading: same weight and secondary description as Account and Overview. */
export default function PageHeader({ title, description, actions }: PageHeaderProps) {
    return (
        <Box
            sx={{
                display: "flex",
                alignItems: "flex-start",
                justifyContent: "space-between",
                gap: 2,
                flexWrap: "wrap",
            }}
        >
            <Box>
                <Typography variant="h4" sx={{ fontWeight: 700 }}>
                    {title}
                </Typography>

                {description && (
                    <Typography sx={{ mt: 1, color: "text.secondary" }}>{description}</Typography>
                )}
            </Box>

            {actions && (
                <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", gap: 1 }}>
                    {actions}
                </Stack>
            )}
        </Box>
    )
}
