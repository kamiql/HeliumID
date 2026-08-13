import { Alert, Box, Button, Chip, Stack } from "@mui/material"
import { CheckCircleOutlined, ErrorOutlined, ShieldOutlined } from "@mui/icons-material"
import { useUser } from "../../../hooks/useUser.ts"
import PageHeader from "../../../components/dashboard/PageHeader.tsx"
import AccountBoxList from "../../../components/dashboard/account/AccountBoxList.tsx"
import { ACCOUNT_ANCHORS } from "../../../components/dashboard/account/AccountRequirement.tsx"
import ProfileBox from "./boxes/ProfileBox.tsx"
import EmailBox from "./boxes/EmailBox.tsx"
import PasswordBox from "./boxes/PasswordBox.tsx"
import TotpBox from "./boxes/TotpBox.tsx"
import PasskeysBox from "./boxes/PasskeysBox.tsx"
import RecoveryCodesBox from "./boxes/RecoveryCodesBox.tsx"
import LinkedProvidersBox from "./boxes/LinkedProvidersBox.tsx"
import SessionsBox from "./boxes/SessionsBox.tsx"
import TrustedDevicesBox from "./boxes/TrustedDevicesBox.tsx"
import DangerZoneBox from "./boxes/DangerZoneBox.tsx"

/**
 * The signed-in account area.
 *
 * The page owns the layout: boxes are grouped by what the user came to do — who they are,
 * how they sign in, what is connected, what is signed in — and each group is a named landmark
 * rather than one more card in an undifferentiated grid.
 */
export default function AccountPage() {
    const user = useUser()

    return (
        <Box sx={{ width: "100%", maxWidth: 1040, mx: "auto", minWidth: 0 }}>
            <PageHeader
                title="Account"
                description="Manage your personal information and account security."
                meta={
                    <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
                        <Chip
                            size="small"
                            variant="outlined"
                            color={user.email_verified ? "success" : "warning"}
                            icon={user.email_verified ? <CheckCircleOutlined /> : <ErrorOutlined />}
                            label={user.email_verified ? "Email verified" : "Email unverified"}
                        />

                        <Chip
                            size="small"
                            variant="outlined"
                            color={user.mfa_enabled ? "success" : "default"}
                            icon={user.mfa_enabled ? <CheckCircleOutlined /> : <ShieldOutlined />}
                            label={user.mfa_enabled ? "Two-factor on" : "Two-factor off"}
                        />
                    </Stack>
                }
            />

            {!user.email_verified && (
                <Alert
                    severity="warning"
                    sx={{ mt: 3 }}
                    action={
                        <Button color="inherit" size="small" href={`#${ACCOUNT_ANCHORS.email}`}>
                            Email settings
                        </Button>
                    }
                >
                    Your email is not verified yet, some actions may not be available
                </Alert>
            )}

            <Stack sx={{ gap: { xs: 4, md: 5 }, mt: 4 }}>
                <AccountBoxList title="Profile">
                    <ProfileBox />
                    <EmailBox />
                </AccountBoxList>

                <AccountBoxList title="Sign-in & security">
                    <TotpBox />
                    <PasskeysBox />
                    <PasswordBox />
                    <RecoveryCodesBox />
                </AccountBoxList>

                <AccountBoxList title="Connections" columns={1}>
                    <LinkedProvidersBox />
                </AccountBoxList>

                <AccountBoxList title="Devices" columns={1}>
                    <SessionsBox />
                    <TrustedDevicesBox />
                </AccountBoxList>

                <AccountBoxList title="Danger zone" columns={1}>
                    <DangerZoneBox />
                </AccountBoxList>
            </Stack>
        </Box>
    )
}
