import {
    Avatar,
    Box,
    Button,
    CircularProgress,
    Container,
    Divider,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Paper,
    Stack,
    Typography,
} from "@mui/material"
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutlineOutlined"
import VerifiedUserOutlinedIcon from "@mui/icons-material/VerifiedUserOutlined"
import { useEffect, useRef, useState } from "react"
import { useSearchParams } from "react-router"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { navigateToAuthorize, oauthApi } from "../../api/oauth.ts"
import { ErrorCode, toHeliumError } from "../../api/problem.ts"
import { useAuthStore } from "../../stores/auth.store.ts"
import type { ConsentPrompt } from "../../api/types.ts"

/**
 * The built-in consent screen, served for `/oauth2/authorize`.
 *
 * Caddy hands `/oauth2/authorize` to the SPA, so this page replays the exact query string
 * against the API. When the backend answers with a [ConsentPrompt] we render it; when it does
 * not need consent it replies with a redirect that XHR cannot follow across origins, so we hand
 * the browser to the real endpoint instead.
 *
 * Approval is a full-page navigation with `consent=granted`: the authorization code must travel
 * from the server straight to the relying party's redirect URI and never through this app.
 */
export default function ConsentPage() {
    const [searchParams] = useSearchParams()
    const user = useAuthStore((state) => state.user)

    const [prompt, setPrompt] = useState<ConsentPrompt | null>(null)
    const [error, setError] = useState<unknown>(null)
    const [loading, setLoading] = useState(true)
    const requested = useRef(false)

    useEffect(() => {
        if (requested.current) return
        requested.current = true

        oauthApi
            .prompt(searchParams)
            .then(({ data }) => {
                // A 302 to a same-origin location would be followed transparently by XHR and
                // hand us the wrong document, so only a real prompt payload is rendered.
                if (!data || typeof data.client_id !== "string") {
                    navigateToAuthorize(searchParams, false)
                    return
                }
                setPrompt(data)
                setLoading(false)
            })
            .catch((caught: unknown) => {
                const heliumError = toHeliumError(caught)

                if (heliumError.is(ErrorCode.AUTH_REQUIRED)) {
                    // The endpoint answers with a redirect to /login for anonymous callers;
                    // let the backend own that decision rather than guessing the return URL.
                    navigateToAuthorize(searchParams, false)
                    return
                }

                if (heliumError.is(ErrorCode.UNKNOWN, ErrorCode.NETWORK)) {
                    // Most likely the 302 we cannot follow from XHR. Retry as a navigation.
                    navigateToAuthorize(searchParams, false)
                    return
                }

                setError(heliumError)
                setLoading(false)
            })
    }, [searchParams])

    if (loading) {
        return (
            <Container maxWidth="xs">
                <Stack spacing={2} sx={{ alignItems: "center" }}>
                    <CircularProgress />
                    <Typography sx={{ color: "text.secondary" }}>Preparing authorization…</Typography>
                </Stack>
            </Container>
        )
    }

    if (error !== null || !prompt) {
        return (
            <Container maxWidth="xs">
                <Paper elevation={8} sx={{ p: 4, borderRadius: 3 }}>
                    <Stack spacing={2}>
                        <Typography variant="h6" sx={{ fontWeight: 600 }}>
                            Authorization failed
                        </Typography>

                        <ErrorAlert error={error} />

                        <Typography variant="body2" sx={{ color: "text.secondary" }}>
                            Return to the application that sent you here and try again.
                        </Typography>
                    </Stack>
                </Paper>
            </Container>
        )
    }

    return (
        <Container component="main" maxWidth="sm">
            <Paper
                elevation={8}
                sx={{
                    p: 4,
                    width: "100%",
                    borderRadius: 3,
                    backgroundColor: "background.paper",
                }}
            >
                <Stack spacing={3} sx={{ alignItems: "center" }}>
                    <Avatar sx={{ bgcolor: "primary.main" }}>
                        <VerifiedUserOutlinedIcon />
                    </Avatar>

                    <Box sx={{ textAlign: "center" }}>
                        <Typography component="h1" variant="h5" sx={{ fontFamily: "Silkscreen" }}>
                            Authorize
                        </Typography>

                        <Typography sx={{ mt: 1.5, color: "text.secondary" }}>
                            <strong>{prompt.client_name}</strong> wants to access your HeliumID
                            account
                            {user ? ` (${user.email})` : ""}.
                        </Typography>
                    </Box>

                    <Divider flexItem />

                    <Box sx={{ width: "100%" }}>
                        <Typography variant="subtitle2" sx={{ mb: 1 }}>
                            This will allow it to:
                        </Typography>

                        <List dense disablePadding>
                            {prompt.scopes.map((scope) => (
                                <ListItem key={scope.name} disableGutters>
                                    <ListItemIcon sx={{ minWidth: 34 }}>
                                        <CheckCircleOutlineIcon fontSize="small" color="primary" />
                                    </ListItemIcon>

                                    <ListItemText
                                        primary={scope.description}
                                        secondary={scope.name}
                                        slotProps={{
                                            secondary: { sx: { fontFamily: "monospace" } },
                                        }}
                                    />
                                </ListItem>
                            ))}
                        </List>
                    </Box>

                    <Stack direction="row" spacing={2} sx={{ width: "100%" }}>
                        <Button
                            fullWidth
                            variant="outlined"
                            color="inherit"
                            onClick={() => {
                                // Denying never redirects anywhere the user did not come from:
                                // bouncing to an unvalidated URI would be an open redirect.
                                if (window.history.length > 1) {
                                    window.history.back()
                                } else {
                                    window.location.assign("/")
                                }
                            }}
                        >
                            Deny
                        </Button>

                        <Button
                            fullWidth
                            variant="contained"
                            onClick={() => navigateToAuthorize(searchParams, true)}
                        >
                            Allow
                        </Button>
                    </Stack>

                    <Typography variant="caption" sx={{ color: "text.secondary", textAlign: "center" }}>
                        You can revoke this access at any time from your account settings.
                    </Typography>
                </Stack>
            </Paper>
        </Container>
    )
}
