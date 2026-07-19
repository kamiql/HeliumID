import {
    Chip,
} from "@mui/material"
import {useState} from "react"
import AccountBox from "../../../../components/dashboard/account/AccountBox.tsx";
import AccountButton from "../../../../components/dashboard/account/AccountButton.tsx";
import {useAuthStore} from "../../../../stores/auth.store.ts"
import {useUser} from "../../../../hooks/useUser.ts"
import {userApi} from "../../../../api/user.ts"
import VerificationDialog from "../../../../components/VerificationDialog.tsx"

export default function EmailVerificationBox() {
    const user = useUser()
    const initialize = useAuthStore((state) => state.initialize)

    const [verificationId, setVerificationId] = useState<string | null>(null)
    const [verificationOpen, setVerificationOpen] = useState(false)
    const [loading, setLoading] = useState(false)

    const handleVerify = async () => {
        try {
            setLoading(true)

            const response = await userApi.verifyEmail()

            setVerificationId(response.data)
            setVerificationOpen(true)
        } catch {
            setLoading(false)
        }
    }

    const handleCompleted = async () => {
        await initialize()

        setVerificationOpen(false)
        setVerificationId(null)
        setLoading(false)
    }

    return (
        <>
            <AccountBox
                title="Email verification"
                description="Verify your email address to secure your account."
                sx={{
                    flex: "1 1 300px",
                    minWidth: "30%",
                }}
            >
                <Chip
                    label={
                        user.emailVerified
                            ? "Email verified"
                            : "Email not verified"
                    }
                    color={
                        user.emailVerified
                            ? "success"
                            : "warning"
                    }
                    variant="outlined"
                    sx={{
                        width: "fit-content",
                    }}
                />

                <AccountButton
                    variant="outlined"
                    disabled={
                        user.emailVerified ||
                        loading
                    }
                    onClick={handleVerify}
                >
                    Verify email
                </AccountButton>
            </AccountBox>

            <VerificationDialog
                open={verificationOpen}
                verificationId={verificationId}
                onClose={() => {
                    setVerificationOpen(false)
                    setVerificationId(null)
                    setLoading(false)
                }}
                onCompleted={handleCompleted}
            />
        </>
    )
}