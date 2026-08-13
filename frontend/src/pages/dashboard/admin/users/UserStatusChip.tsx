import { Box, Chip, Tooltip, type ChipProps } from "@mui/material"

const COLORS: Record<string, ChipProps["color"]> = {
    ACTIVE: "success",
    PENDING_EMAIL_VERIFICATION: "warning",
    SUSPENDED: "error",
    LOCKED: "error",
    DELETED: "default",
}

/**
 * What each status actually does to the account.
 *
 * The chip label is the wire value in prose; these say what it *means*, because "locked" and
 * "suspended" both read as "cannot sign in" until you know which one lifts by itself.
 */
const MEANINGS: Record<string, string> = {
    ACTIVE: "Can sign in normally.",
    PENDING_EMAIL_VERIFICATION: "Registered but the email address is unconfirmed.",
    SUSPENDED: "Sign-in refused until an administrator reactivates the account.",
    LOCKED: "Sign-in temporarily blocked after repeated failures.",
    DELETED: "Erased from the directory; the record is retained for audit only.",
}

export default function UserStatusChip({ status }: { status: string }) {
    const chip = (
        <Chip
            label={status.replace(/_/g, " ").toLowerCase()}
            color={COLORS[status] ?? "default"}
            size="small"
            variant="outlined"
            sx={{ textTransform: "capitalize" }}
        />
    )

    const meaning = MEANINGS[status]
    if (!meaning) return chip

    // Supplementary only: the chip's own label already names the status, so the tooltip adds
    // detail without becoming one extra tab stop on every row of a 100-row table.
    return (
        <Tooltip title={meaning}>
            <Box component="span" sx={{ display: "inline-flex" }}>
                {chip}
            </Box>
        </Tooltip>
    )
}
