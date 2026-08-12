import { Alert, Box, Typography } from "@mui/material"
import { useUser } from "../../../hooks/useUser.ts"
import AccountBoxList, {
    type AccountBoxDefinition,
} from "../../../components/dashboard/account/AccountBoxList.tsx"
import ProfileBox from "./boxes/ProfileBox.tsx"
import EmailBox from "./boxes/EmailBox.tsx"
import PasswordBox from "./boxes/PasswordBox.tsx"
import TotpBox from "./boxes/TotpBox.tsx"
import RecoveryCodesBox from "./boxes/RecoveryCodesBox.tsx"
import LinkedProvidersBox from "./boxes/LinkedProvidersBox.tsx"
import SessionsBox from "./boxes/SessionsBox.tsx"
import DangerZoneBox from "./boxes/DangerZoneBox.tsx"

const boxes: AccountBoxDefinition[] = [
    { component: ProfileBox },
    { component: EmailBox },
    { component: PasswordBox },
    { component: TotpBox },
    { component: RecoveryCodesBox },
    { component: LinkedProvidersBox },
    { component: SessionsBox },
    { component: DangerZoneBox },
]

export default function AccountPage() {
    const user = useUser()

    return (
        <Box
            sx={{
                width: "100%",
                maxWidth: 900,
                mx: "auto",
                px: {
                    xs: 1,
                    sm: 0,
                },
                minWidth: 0,
            }}
        >
            {!user.email_verified && (
                <Alert
                    severity="warning"
                    sx={{
                        mb: 2,
                    }}
                >
                    Your email is not verified yet, some actions may not be available
                </Alert>
            )}

            <Box sx={{ mb: 4 }}>
                <Typography
                    variant="h4"
                    sx={{
                        fontWeight: 700,
                    }}
                >
                    Account
                </Typography>

                <Typography
                    sx={{
                        mt: 1,
                        color: "text.secondary",
                    }}
                >
                    Manage your personal information and account security.
                </Typography>
            </Box>

            <Box
                sx={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 3,
                }}
            >
                <AccountBoxList boxes={boxes} />
            </Box>
        </Box>
    )
}
