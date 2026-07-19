import {
    Box,
    Typography,
} from "@mui/material"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx";
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx";
import {useConfirm} from "../../../../hooks/useConfirm.ts"
import {userApi} from "../../../../api/user.ts"
import {useAuthStore} from "../../../../stores/auth.store.ts"

export default function DangerZoneBox() {
    const {confirm} = useConfirm()
    const initialize = useAuthStore((state) => state.initialize)

    const handleDelete = async () => {
        const confirmed = await confirm({
            title: "Delete account?",
            message: "This permanently deletes your account and cannot be undone.",
            confirmText: "Delete account",
        })

        if (!confirmed) return

        await userApi.deleteAccount()
        await initialize()
    }

    return (
        <AccountBox
            title="Danger Zone"
            description="Permanently delete your account and all associated data."
            sx={{
                flex: "1 1 100%",
                border: "1px solid",
                borderColor: "error.main",
            }}
        >
            <Box
                sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 2,
                    flexWrap: "wrap",
                }}
            >
                <Typography variant="body2">
                    This action cannot be undone.
                </Typography>

                <AccountButton
                    variant="contained"
                    color="error"
                    onClick={handleDelete}
                >
                    Delete account
                </AccountButton>
            </Box>
        </AccountBox>
    )
}