import {
    Alert,
    Box,
    Typography,
} from "@mui/material"
import {useUser} from "../../../hooks/useUser.ts"
import PersonalInformationBox from "./boxes/PersonalInformationBox.tsx"
import PasswordBox from "./boxes/PasswordBox.tsx"
import EmailVerificationBox from "./boxes/EmailVerificationBox.tsx"
import ConnectedAccountsBox from "./boxes/ConnectedAccountsBox.tsx"
import TotpBox from "./boxes/TotpBox.tsx"
import DangerZoneBox from "./boxes/DangerZoneBox.tsx"
import AccountBoxList, {type AccountBoxDefinition} from "../../../components/dashboard/account/AccountBoxList.tsx";

export default function AccountPage() {
    const user = useUser()

    const boxes: AccountBoxDefinition[] = [
        {
            component: PersonalInformationBox,
        },
        {
            component: PasswordBox,
        },
        {
            component: EmailVerificationBox,
        },
        {
            component: ConnectedAccountsBox,
        },
        {
            component: TotpBox,
        },
        {
            component: DangerZoneBox,
        },
    ]

    return (
        <Box
            sx={{
                maxWidth: 900,
                mx: "auto",
            }}
        >
            {!user.emailVerified && (
                <Alert
                    severity="warning"
                    sx={{
                        mb: 2,
                    }}
                >
                    Your email is not verified yet, some actions may not be available
                </Alert>
            )}

            <Box sx={{mb: 4}}>
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
                <AccountBoxList boxes={boxes}/>
            </Box>
        </Box>
    )
}