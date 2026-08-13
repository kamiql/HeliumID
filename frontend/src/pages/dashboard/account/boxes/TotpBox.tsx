import {
    Alert,
    Box,
    Chip,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import { CheckCircleOutlined, ShieldOutlined } from "@mui/icons-material"
import { QRCodeSVG } from "qrcode.react"
import { useEffect, useState } from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx"
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx"
import { ACCOUNT_ANCHORS } from "../../../../components/dashboard/account/AccountRequirement.tsx"
import DefinitionList from "../../../../components/ui/DefinitionList.tsx"
import { ListSkeleton } from "../../../../components/ui/StateView.tsx"
import OtpInput from "../../../../components/OtpInput.tsx"
import PasswordField from "../../../../components/PasswordField.tsx"
import CopyButton from "../../../../components/CopyButton.tsx"
import ErrorAlert from "../../../../components/ErrorAlert.tsx"
import OneTimeSecretDialog from "../../../../components/OneTimeSecretDialog.tsx"
import { useUser } from "../../../../hooks/useUser.ts"
import { useAuthStore } from "../../../../stores/auth.store.ts"
import { accountApi } from "../../../../api/account.ts"
import { toHeliumError } from "../../../../api/problem.ts"
import { formatDateTime, formatRelative } from "../../../../lib/format.ts"
import { MONO_FONT } from "../../../../lib/theme.ts"
import { notify } from "../../../../stores/notice.store.ts"
import type { MfaFactor, TotpEnrollment } from "../../../../api/types.ts"

/**
 * TOTP enrollment.
 *
 * The QR code is rendered locally from the `otpauth_uri` the server returns. Round-tripping the
 * secret through an external QR service would hand the shared secret to a third party, so the
 * code is drawn client-side and the URI never leaves the browser.
 */
export default function TotpBox() {
    const user = useUser()
    const refresh = useAuthStore((state) => state.refresh)

    const [factors, setFactors] = useState<MfaFactor[]>([])
    const [factorsLoading, setFactorsLoading] = useState(true)
    const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null)
    const [code, setCode] = useState("")
    const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)

    const [disableOpen, setDisableOpen] = useState(false)
    const [password, setPassword] = useState("")

    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<unknown>(null)

    const activeTotp = factors.find((factor) => factor.type === "totp" && factor.status === "ACTIVE")

    // No `setFactorsLoading(true)` here: the flag starts true for the first fetch, and a
    // refresh after enrolling or disabling should update the detail in place rather than
    // replace it with a skeleton.
    const loadFactors = () => {
        accountApi
            .factors()
            .then(({ data }) => setFactors(data))
            .catch(() => setFactors([]))
            .finally(() => setFactorsLoading(false))
    }

    useEffect(loadFactors, [])

    const handleEnroll = async () => {
        try {
            setLoading(true)
            setError(null)
            const { data } = await accountApi.enrollTotp()
            setEnrollment(data)
            setCode("")
        } catch (caught) {
            setError(caught)
        } finally {
            setLoading(false)
        }
    }

    const handleConfirm = async (value = code) => {
        if (!enrollment || value.length !== 6 || loading) return

        try {
            setLoading(true)
            setError(null)

            const { data } = await accountApi.confirmTotp({
                factor_id: enrollment.factor_id,
                code: value,
            })

            setEnrollment(null)
            setCode("")
            // Recovery codes come back exactly once, here and nowhere else.
            setRecoveryCodes(data.codes)
            loadFactors()
            void refresh()
        } catch (caught) {
            setCode("")
            setError(caught)
        } finally {
            setLoading(false)
        }
    }

    const handleDisable = async () => {
        if (!activeTotp) return

        try {
            setLoading(true)
            setError(null)

            await accountApi.disableTotp({
                factor_id: activeTotp.id,
                current_password: password || null,
            })

            setDisableOpen(false)
            setPassword("")
            loadFactors()
            void refresh()
            notify("Two-factor authentication disabled.", "warning")
        } catch (caught) {
            setError(toHeliumError(caught))
        } finally {
            setLoading(false)
        }
    }

    return (
        <>
            <AccountBox
                id={ACCOUNT_ANCHORS.totp}
                title="Two-factor authentication"
                description="Protect your account with a time-based code from an authenticator app."
                requirements={[
                    {
                        id: "email",
                        label: "Verify your email address first",
                        hint: "Two-factor setup relies on an address we can reach if you lose the app.",
                        fix: { label: "Go to email address", anchor: ACCOUNT_ANCHORS.email },
                        satisfied: user.email_verified || user.mfa_enabled,
                    },
                ]}
                banner={
                    <Chip
                        size="small"
                        variant="outlined"
                        color={user.mfa_enabled ? "success" : "default"}
                        icon={user.mfa_enabled ? <CheckCircleOutlined /> : <ShieldOutlined />}
                        label={user.mfa_enabled ? "Enabled" : "Not enabled"}
                    />
                }
                actions={
                    activeTotp ? (
                        <AccountButton
                            variant="outlined"
                            color="error"
                            aria-label="Disable two-factor authentication"
                            onClick={() => {
                                setError(null)
                                setPassword("")
                                setDisableOpen(true)
                            }}
                        >
                            Disable
                        </AccountButton>
                    ) : (
                        <AccountButton
                            variant="contained"
                            aria-label="Set up two-factor authentication"
                            onClick={() => void handleEnroll()}
                            disabled={loading || factorsLoading}
                        >
                            Set up
                        </AccountButton>
                    )
                }
            >
                <Stack sx={{ gap: 2 }}>
                    {error !== null && !enrollment && !disableOpen && <ErrorAlert error={error} />}

                    {factorsLoading ? (
                        <ListSkeleton rows={1} lines={2} />
                    ) : activeTotp ? (
                        <>
                            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                                Signing in asks for a six-digit code from this authenticator, on
                                top of your password.
                            </Typography>

                            <DefinitionList
                                items={[
                                    {
                                        label: "Authenticator",
                                        value: activeTotp.label || "Authenticator app",
                                    },
                                    { label: "Added", value: formatDateTime(activeTotp.created_at) },
                                    {
                                        label: "Last used",
                                        value: activeTotp.last_used_at
                                            ? formatRelative(activeTotp.last_used_at)
                                            : "Never used",
                                    },
                                ]}
                            />
                        </>
                    ) : (
                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Nothing but your password protects this account right now. Adding an
                            authenticator app means a stolen password is not enough on its own.
                        </Typography>
                    )}
                </Stack>
            </AccountBox>

            <Dialog
                open={enrollment !== null}
                onClose={() => {
                    if (loading) return
                    setEnrollment(null)
                    setCode("")
                    setError(null)
                }}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Set up two-factor authentication</DialogTitle>

                <DialogContent>
                    <Stack spacing={2}>
                        <Typography variant="body2">
                            Scan this code with your authenticator app, then enter the six digits
                            it shows.
                        </Typography>

                        {enrollment && (
                            <>
                                <Box
                                    sx={{
                                        mx: "auto",
                                        p: 2,
                                        // A white quiet zone regardless of theme: scanners need
                                        // the contrast, and the dark palette would break them.
                                        backgroundColor: "#FFFFFF",
                                        borderRadius: 2,
                                        lineHeight: 0,
                                    }}
                                >
                                    <QRCodeSVG
                                        value={enrollment.otpauth_uri}
                                        size={200}
                                        level="M"
                                        marginSize={0}
                                    />
                                </Box>

                                <Box>
                                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                                        Can&apos;t scan? Enter this key manually
                                    </Typography>

                                    <Stack
                                        direction="row"
                                        spacing={1}
                                        sx={{ alignItems: "center", mt: 0.5 }}
                                    >
                                        <Typography
                                            sx={{
                                                fontFamily: MONO_FONT,
                                                wordBreak: "break-all",
                                                flex: 1,
                                            }}
                                        >
                                            {enrollment.secret}
                                        </Typography>

                                        <CopyButton value={enrollment.secret} iconOnly />
                                    </Stack>
                                </Box>
                            </>
                        )}

                        <OtpInput
                            value={code}
                            onChange={(value) => {
                                setCode(value)
                                setError(null)
                                if (value.length === 6) void handleConfirm(value)
                            }}
                            autoFocus
                        />

                        {error !== null && <ErrorAlert error={error} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <AccountButton
                        onClick={() => {
                            setEnrollment(null)
                            setCode("")
                        }}
                        disabled={loading}
                    >
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        onClick={() => void handleConfirm()}
                        disabled={loading || code.length !== 6}
                    >
                        Enable
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <Dialog
                open={disableOpen}
                onClose={() => {
                    if (loading) return
                    setDisableOpen(false)
                    setError(null)
                }}
                fullWidth
                maxWidth="xs"
            >
                <DialogTitle>Disable two-factor authentication</DialogTitle>

                <DialogContent>
                    <Stack spacing={2} sx={{ mt: 1 }}>
                        <Alert severity="warning">
                            Your account will be protected by your password alone. Existing
                            recovery codes stop working.
                        </Alert>

                        <PasswordField
                            fullWidth
                            autoFocus
                            label="Current password"
                            autoComplete="current-password"
                            value={password}
                            onType={(value) => {
                                setPassword(value)
                                setError(null)
                            }}
                        />

                        {error !== null && <ErrorAlert error={error} />}
                    </Stack>
                </DialogContent>

                <DialogActions>
                    <AccountButton onClick={() => setDisableOpen(false)} disabled={loading}>
                        Cancel
                    </AccountButton>

                    <AccountButton
                        variant="contained"
                        color="error"
                        onClick={() => void handleDisable()}
                        disabled={loading}
                    >
                        Disable
                    </AccountButton>
                </DialogActions>
            </Dialog>

            <OneTimeSecretDialog
                open={recoveryCodes !== null}
                title="Save your recovery codes"
                description="Each code signs you in once if you lose your authenticator app. Store them somewhere other than the device running the app."
                values={recoveryCodes ?? []}
                downloadFileName="helium-recovery-codes.txt"
                onClose={() => {
                    setRecoveryCodes(null)
                    notify("Two-factor authentication enabled.", "success")
                }}
            />
        </>
    )
}
