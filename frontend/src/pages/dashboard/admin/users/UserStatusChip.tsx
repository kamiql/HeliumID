import { Chip, type ChipProps } from "@mui/material"

const COLORS: Record<string, ChipProps["color"]> = {
    ACTIVE: "success",
    PENDING_EMAIL_VERIFICATION: "warning",
    SUSPENDED: "error",
    LOCKED: "error",
    DELETED: "default",
}

export default function UserStatusChip({ status }: { status: string }) {
    return (
        <Chip
            label={status.replace(/_/g, " ").toLowerCase()}
            color={COLORS[status] ?? "default"}
            size="small"
            variant="outlined"
            sx={{ textTransform: "capitalize" }}
        />
    )
}
