import {
    Box,
    Button,
    CircularProgress,
    Skeleton,
    Stack,
    TableCell,
    TableRow,
    Typography,
} from "@mui/material"
import type { SxProps, Theme } from "@mui/material/styles"
import type { ElementType, ReactNode } from "react"

/**
 * The four states every data-backed view has to answer for: loading, empty, error, and the
 * data itself. They are components rather than a convention so no screen can quietly skip
 * one and leave the user staring at a blank panel.
 */

type EmptyStateProps = {
    /** A concrete outline icon from `@mui/icons-material`. */
    icon?: ElementType
    title: string
    /** Why it is empty and what to do about it — never a bare "No data". */
    description?: string
    action?: ReactNode
    dense?: boolean
    sx?: SxProps<Theme>
}

export function EmptyState({
    icon: Icon,
    title,
    description,
    action,
    dense = false,
    sx,
}: EmptyStateProps) {
    return (
        <Stack
            sx={{
                alignItems: "center",
                textAlign: "center",
                gap: 1,
                py: dense ? 3 : 6,
                px: 2,
                ...sx,
            }}
        >
            {Icon && (
                <Box
                    aria-hidden
                    sx={{
                        display: "grid",
                        placeItems: "center",
                        width: dense ? 40 : 48,
                        height: dense ? 40 : 48,
                        borderRadius: "50%",
                        mb: 0.5,
                        color: "text.secondary",
                        backgroundColor: "action.hover",
                    }}
                >
                    <Icon fontSize={dense ? "small" : "medium"} />
                </Box>
            )}

            <Typography variant="subtitle1">{title}</Typography>

            {description && (
                <Typography variant="body2" sx={{ color: "text.secondary", maxWidth: 420 }}>
                    {description}
                </Typography>
            )}

            {action && <Box sx={{ mt: 1.5 }}>{action}</Box>}
        </Stack>
    )
}

type LoadingStateProps = {
    /** Announced to screen readers and shown beside the spinner. */
    label?: string
    dense?: boolean
    sx?: SxProps<Theme>
}

export function LoadingState({ label = "Loading…", dense = false, sx }: LoadingStateProps) {
    return (
        <Stack
            role="status"
            aria-live="polite"
            sx={{ alignItems: "center", gap: 1.5, py: dense ? 3 : 6, ...sx }}
        >
            <CircularProgress size={dense ? 22 : 30} />
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                {label}
            </Typography>
        </Stack>
    )
}

type ListSkeletonProps = {
    rows?: number
    /** Matches the two-line "title over metadata" shape used by session and device rows. */
    lines?: 1 | 2
}

export function ListSkeleton({ rows = 3, lines = 2 }: ListSkeletonProps) {
    return (
        <Stack aria-hidden sx={{ gap: 2 }}>
            {Array.from({ length: rows }, (_, index) => (
                <Stack key={index} direction="row" sx={{ gap: 1.5, alignItems: "center" }}>
                    <Skeleton variant="circular" width={32} height={32} />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Skeleton variant="text" width="42%" height={20} />
                        {lines === 2 && <Skeleton variant="text" width="68%" height={16} />}
                    </Box>
                </Stack>
            ))}
        </Stack>
    )
}

type TableSkeletonProps = {
    rows?: number
    columns: number
}

/** Placeholder rows that keep the table's column widths stable while the first page loads. */
export function TableSkeleton({ rows = 5, columns }: TableSkeletonProps) {
    return (
        <>
            {Array.from({ length: rows }, (_, row) => (
                <TableRow key={row} aria-hidden>
                    {Array.from({ length: columns }, (_, column) => (
                        <TableCell key={column}>
                            <Skeleton variant="text" width={column === 0 ? "70%" : "45%"} />
                        </TableCell>
                    ))}
                </TableRow>
            ))}
        </>
    )
}

type TableStateRowProps = {
    columns: number
    children: ReactNode
}

/** Wraps an empty or error state so it spans the full table width. */
export function TableStateRow({ columns, children }: TableStateRowProps) {
    return (
        <TableRow>
            <TableCell colSpan={columns} sx={{ borderBottom: "none" }}>
                {children}
            </TableCell>
        </TableRow>
    )
}

type RetryButtonProps = {
    onRetry: () => void
    label?: string
}

/** The follow-up action an error state should always offer when the call can be repeated. */
export function RetryButton({ onRetry, label = "Try again" }: RetryButtonProps) {
    return (
        <Button color="inherit" size="small" onClick={onRetry}>
            {label}
        </Button>
    )
}
