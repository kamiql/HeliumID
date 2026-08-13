import { Alert, Stack, Typography } from "@mui/material"
import { useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { ACCOUNT_ANCHORS } from "../../../../components/dashboard/account/AccountRequirement.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import OneTimeSecretDialog from "../../../../components/OneTimeSecretDialog.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { accountApi } from "../../../../api/account.ts"

/**
 * Regenerating replaces the whole set — every previously issued code stops working.
 *
 * Codes are stored hashed, exactly like passwords, so there is no way to show an existing set
 * again; the only recovery from a lost list is a new one. For the same reason the page cannot
 * say how many are left: the server has nothing to count that it would be willing to reveal.
 */
export default function RecoveryCodesBox() {
    const user = useUser()
    const { confirm } = useConfirm()

    const [codes, setCodes] = useState<string[] | null>(null)
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(false)

    const handleRegenerate = async () => {
        const confirmed = await confirm({
            title: "Regenerate recovery codes?",
            message:
                "Every code from your current list stops working the moment the new set is created. Make sure you can save the new codes before you continue.",
            confirmText: "Regenerate",
        })

        if (!confirmed) return

        try {
            setLoading(true)
            setError(null)
            const { data } = await accountApi.regenerateRecoveryCodes()
            setCodes(data.codes)
        } catch (caught) {
            setError(caught)
        } finally {
            setLoading(false)
        }
    }

    return (
        <>
            <AccountBox
                title="Recovery codes"
                description="Single-use codes that get you back in if you lose your authenticator."
                requirements={[
                    {
                        id: "mfa",
                        label: "Turn on two-factor authentication first",
                        hint: "Recovery codes only exist once there is a second factor to recover from.",
                        fix: {
                            label: "Go to two-factor authentication",
                            anchor: ACCOUNT_ANCHORS.totp,
                        },
                        satisfied: user.mfa_enabled,
                    },
                ]}
                actions={
                    <AccountButton
                        variant="outlined"
                        onClick={() => void handleRegenerate()}
                        disabled={loading}
                        aria-label="Regenerate recovery codes"
                    >
                        Regenerate
                    </AccountButton>
                }
            >
                <Stack sx={{ gap: 2 }}>
                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        Codes are shown once, when they are generated, and stored only as hashes —
                        so we cannot show your current set again or tell you how many are left. If
                        you are not sure you still have them, generate a new set.
                    </Typography>

                    <Alert severity="warning">
                        Generating a new set invalidates every earlier code immediately, including
                        any you have printed or saved elsewhere.
                    </Alert>

                    {error !== null && <ErrorAlert error={error} />}
                </Stack>
            </AccountBox>

            <OneTimeSecretDialog
                open={codes !== null}
                title="Your new recovery codes"
                description="These replace every code issued before. Each one works exactly once."
                values={codes ?? []}
                downloadFileName="helium-recovery-codes.txt"
                onClose={() => setCodes(null)}
            />
        </>
    )
}
