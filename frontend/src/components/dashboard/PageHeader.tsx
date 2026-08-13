import { NavigateNext } from "@mui/icons-material"
import { Box, Breadcrumbs, Link as MuiLink, Stack, Typography } from "@mui/material"
import type { ReactNode } from "react"
import { Link } from "react-router"

export type Crumb = {
    label: string
    /** Omit on the current page — the last crumb is never a link. */
    to?: string
}

type PageHeaderProps = {
    title: string
    /** One sentence of context. Says what the page is for, not what it is called. */
    description?: string
    /** Primary action first; anything secondary uses a quieter variant. */
    actions?: ReactNode
    /** Trail above the title. The current page is added automatically from `title`. */
    breadcrumbs?: Crumb[]
    /** Status chips or counts, shown beside the title. */
    meta?: ReactNode
}

/**
 * The heading block every dashboard page starts with.
 *
 * It owns the single `h1` on the page, so the document outline stays correct no matter which
 * route is mounted, and it fixes where primary actions live: top-right on wide screens,
 * stacked under the description on narrow ones.
 */
export default function PageHeader({
    title,
    description,
    actions,
    breadcrumbs,
    meta,
}: PageHeaderProps) {
    return (
        <Box component="header">
            {breadcrumbs && breadcrumbs.length > 0 && (
                <Breadcrumbs
                    aria-label="Breadcrumb"
                    separator={<NavigateNext fontSize="small" />}
                    sx={{ mb: 1 }}
                >
                    {breadcrumbs.map((crumb) =>
                        crumb.to ? (
                            <MuiLink
                                key={crumb.label}
                                component={Link}
                                to={crumb.to}
                                color="text.secondary"
                            >
                                {crumb.label}
                            </MuiLink>
                        ) : (
                            <Typography key={crumb.label} variant="body2" color="text.secondary">
                                {crumb.label}
                            </Typography>
                        ),
                    )}

                    <Typography variant="body2" color="text.primary" aria-current="page">
                        {title}
                    </Typography>
                </Breadcrumbs>
            )}

            <Stack
                direction={{ xs: "column", md: "row" }}
                sx={{
                    gap: 2,
                    alignItems: { md: "flex-start" },
                    justifyContent: "space-between",
                }}
            >
                <Box sx={{ minWidth: 0 }}>
                    <Stack
                        direction="row"
                        sx={{ gap: 1.5, alignItems: "center", flexWrap: "wrap" }}
                    >
                        <Typography variant="h4" component="h1" sx={{ wordBreak: "break-word" }}>
                            {title}
                        </Typography>

                        {meta}
                    </Stack>

                    {description && (
                        <Typography
                            variant="body2"
                            sx={{ mt: 1, color: "text.secondary", maxWidth: "68ch" }}
                        >
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
        </Box>
    )
}
