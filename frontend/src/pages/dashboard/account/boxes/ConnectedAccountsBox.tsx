import {
    Box,
    Chip,
    Stack,
    Typography,
} from "@mui/material"
import CheckCircleIcon from "@mui/icons-material/CheckCircle"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx";
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx";
import {useUser} from "../../../../hooks/useUser.ts"
import {useAuthStore} from "../../../../stores/auth.store.ts"
import {userApi} from "../../../../api/user.ts"
import {authApi} from "../../../../api/auth.ts"
import {DiscordIcon, GoogleIcon} from "../../../../components/global/Icons.tsx"
import {useConfirm} from "../../../../hooks/useConfirm.ts"

const PROVIDERS = [
    {id: "google", name: "Google", icon: GoogleIcon},
    {id: "discord", name: "Discord", icon: DiscordIcon},
] as const

export default function ConnectedAccountsBox() {
    const user = useUser()
    const initialize = useAuthStore((state) => state.initialize)
    const {confirm} = useConfirm()

    const linkedAccounts = user.linkedAccounts ?? {}

    const handleRemove = async (provider: string) => {
        const confirmed = await confirm({
            title: "Remove?",
            message: "This cannot be undone.",
            confirmText: "Remove",
        })

        if (!confirmed) return

        await userApi.removeOauthProvider(provider)
        await initialize()
    }

    return (
        <AccountBox
            title="Connected Accounts"
            description="Link your social accounts for seamless sign-in."
            requirements={[
                {
                    id: "email",
                    label: "Email verification required",
                    satisfied: user.emailVerified,
                },
            ]}
            sx={{
                flex: "1 1 300px",
                minWidth: "60%",
            }}
        >
            <Stack spacing={2}>
                {PROVIDERS.map((provider) => {
                    const account =
                        linkedAccounts[provider.id.toUpperCase()]
                    const Icon = provider.icon

                    return (
                        <Box
                            key={provider.id}
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "space-between",
                                gap: 2,
                            }}
                        >
                            <Box
                                sx={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 1.5,
                                    minWidth: 0,
                                }}
                            >
                                <Icon/>

                                <Box sx={{minWidth: 0}}>
                                    <Typography
                                        sx={{
                                            fontWeight: 500,
                                        }}
                                    >
                                        {provider.name}
                                    </Typography>

                                    {account && (
                                        <Typography
                                            variant="body2"
                                            sx={{
                                                color: "text.secondary",
                                                overflow: "hidden",
                                                textOverflow: "ellipsis",
                                                whiteSpace: "nowrap",
                                            }}
                                        >
                                            {account.username}
                                            {account.email &&
                                                ` · ${account.email}`}
                                        </Typography>
                                    )}
                                </Box>
                            </Box>

                            {account ? (
                                <Box
                                    sx={{
                                        display: "flex",
                                        alignItems: "center",
                                        gap: 1,
                                        flexShrink: 0,
                                    }}
                                >
                                    <Chip
                                        label="Linked"
                                        color="success"
                                        size="small"
                                        icon={<CheckCircleIcon/>}
                                    />

                                    <AccountButton
                                        variant="contained"
                                        size="small"
                                        color="error"
                                        onClick={() =>
                                            handleRemove(provider.id)
                                        }
                                    >
                                        Remove
                                    </AccountButton>
                                </Box>
                            ) : (
                                <AccountButton
                                    variant="outlined"
                                    size="small"
                                    onClick={() =>
                                        authApi.oauth(provider.id)
                                    }
                                >
                                    Link
                                </AccountButton>
                            )}
                        </Box>
                    )
                })}
            </Stack>
        </AccountBox>
    )
}