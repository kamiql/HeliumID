import { Box, Typography } from "@mui/material"
import type { SxProps, Theme } from "@mui/material/styles"
import type { ReactNode } from "react"
import { MONO_FONT } from "../../lib/theme.ts"

export type DefinitionItem = {
    label: string
    /** `null`/`undefined` renders an em dash, so an absent value never looks like a bug. */
    value: ReactNode
    /** Renders the value in the monospace face — for IDs, tokens and URIs. */
    mono?: boolean
    /** Lets one entry span the full width, e.g. a long identifier. */
    wide?: boolean
}

type DefinitionListProps = {
    items: DefinitionItem[]
    /** Columns at `sm` and above. One column below that, always. */
    columns?: 1 | 2 | 3
    sx?: SxProps<Theme>
}

/**
 * Label-over-value pairs, rendered as a real `<dl>`.
 *
 * Read-only account and admin detail is the same shape everywhere, and a description list is
 * what a screen reader needs to pair a label with its value.
 */
export default function DefinitionList({ items, columns = 2, sx }: DefinitionListProps) {
    return (
        <Box
            component="dl"
            sx={{
                m: 0,
                display: "grid",
                gridTemplateColumns: {
                    xs: "1fr",
                    sm: `repeat(${columns}, minmax(0, 1fr))`,
                },
                columnGap: 3,
                rowGap: 2.5,
                ...sx,
            }}
        >
            {items.map((item) => (
                <Box
                    key={item.label}
                    sx={{ minWidth: 0, gridColumn: item.wide ? { sm: "1 / -1" } : undefined }}
                >
                    <Typography
                        component="dt"
                        variant="caption"
                        sx={{ color: "text.secondary", fontWeight: 600, letterSpacing: "0.02em" }}
                    >
                        {item.label}
                    </Typography>

                    <Typography
                        component="dd"
                        variant="body2"
                        sx={{
                            m: 0,
                            mt: 0.5,
                            wordBreak: "break-word",
                            ...(item.mono && { fontFamily: MONO_FONT, fontSize: "0.8125rem" }),
                        }}
                    >
                        {item.value ?? "—"}
                    </Typography>
                </Box>
            ))}
        </Box>
    )
}
