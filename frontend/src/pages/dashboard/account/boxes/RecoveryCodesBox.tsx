import { Typography } from "@mui/material"
import { useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import OneTimeSecretDialog from "../../../../components/OneTimeSecretDialog.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useConfirm } from "../../../../hooks/useConfirm.ts"
import { accountApi } from "../../../../api/account.ts"

/**
 * Regenerating replaces the whole set — every previously issued code stops working.
 *
 * Codes are stored hashed, exactly like passwords, so there is no way to show an existing set
 * again; the only recovery from a lost list is a new one.
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
            message: "Your current recovery codes will stop working immediately.",
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
                        label: "Two-factor authentication required",
                        satisfied: user.mfa_enabled,
                    },
                ]}
                sx={{
                    flex: "1 1 300px",
                    minWidth: "250px",
                }}
            >
                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    Codes are shown once when generated. If you have lost yours, generate a new
                    set — the old ones stop working straight away.
                </Typography>

                {error !== null && <ErrorAlert error={error} />}

                <AccountButton
                    variant="outlined"
                    onClick={() => void handleRegenerate()}
                    disabled={loading}
                >
                    Regenerate recovery codes
                </AccountButton>
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
