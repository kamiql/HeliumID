import {
    Avatar,
    Box,
    Button,
    Container,
    Divider,
    Paper,
    Stack,
    Typography,
} from "@mui/material"
import { alpha } from "@mui/material/styles"
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutlineOutlined"
import LockOutlinedIcon from "@mui/icons-material/LockOutlined"
import type { ReactNode } from "react"
import { useEffect, useRef, useState } from "react"
import { Link, useSearchParams } from "react-router"
import Brand from "../../components/global/Brand.tsx"
import ErrorAlert from "../../components/ErrorAlert.tsx"
import { LoadingState } from "../../components/ui/StateView.tsx"
import { navigateToAuthorize, oauthApi } from "../../api/oauth.ts"
import { ErrorCode, toHeliumError } from "../../api/problem.ts"
import { useAuthStore } from "../../stores/auth.store.ts"
import { MONO_FONT } from "../../lib/theme.ts"
import type { ConsentPrompt } from "../../api/types.ts"

/**
 * The card every state of this screen is drawn in.
 *
 * Loading, failure and the prompt itself share one shell so the page never appears to change
 * identity underneath a user who is in the middle of granting access to their account.
 */
function ConsentShell({ title, subtitle, children }: {
    title: string
    subtitle?: ReactNode
    children: ReactNode
}) {
    return (
        <Container component="main" maxWidth="sm" sx={{ px: { xs: 2, sm: 3 } }}>
            <Paper
                elevation={8}
                sx={{
                    p: { xs: 3, sm: 4 },
                    width: "100%",
                    borderRadius: 3,
                    backgroundColor: "background.paper",
                }}
            >
                <Stack spacing={3}>
                    <Stack spacing={2}>
                        <Brand />

                        <Box>
                            <Typography component="h1" variant="h4">
                                {title}
                            </Typography>

                            {subtitle && (
                                <Box sx={{ mt: 1, color: "text.secondary" }}>{subtitle}</Box>
                            )}
                        </Box>
                    </Stack>

                    {children}
                </Stack>
            </Paper>
        </Container>
    )
}

/**
 * The built-in consent screen, served for `/oauth2/authorize`.
 *
 * Caddy routes that path by `Accept`: a browser navigation (`text/html`) lands here, while every
 * other caller — including this page's own XHR below, which asks for JSON — goes straight to the
 * backend. That split is what makes this route reachable at all; without it the browser would
 * render the backend's JSON consent prompt raw.
 *
 * So this page replays the exact query string against the API. When the backend answers with a
 * [ConsentPrompt] we render it; when it does not need consent it replies with a redirect that XHR
 * cannot follow across origins, so we hand the browser to the real endpoint instead.
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
            <ConsentShell
                title="Authorize access"
                subtitle="Checking what this application is asking for."
            >
                <LoadingState label="Preparing authorization…" />
            </ConsentShell>
        )
    }

    if (error !== null || !prompt) {
        return (
            <ConsentShell
                title="Authorization failed"
                subtitle="Nothing was shared and no access was granted."
            >
                <ErrorAlert error={error} />

                <Typography variant="body2" sx={{ color: "text.secondary" }}>
                    Return to the application that sent you here and try again. Starting a new
                    request from the application is the only safe way to continue — this page
                    cannot resume an authorization on its own.
                </Typography>

                <Box>
                    <Button component={Link} to="/" variant="outlined">
                        Go to your account
                    </Button>
                </Box>
            </ConsentShell>
        )
    }

    return (
        <ConsentShell
            title="Authorize access"
            subtitle={
                <>
                    <Box component="strong" sx={{ color: "text.primary", fontWeight: 700 }}>
                        {prompt.client_name}
                    </Box>{" "}
                    is asking to use your HeliumID account.
                </>
            }
        >
            <Stack
                direction="row"
                sx={{
                    gap: 1.5,
                    alignItems: "center",
                    p: 1.5,
                    borderRadius: 2,
                    border: "1px solid",
                    borderColor: "divider",
                    backgroundColor: (theme) => alpha(theme.palette.primary.main, 0.06),
                }}
            >
                <Avatar sx={{ bgcolor: "primary.main", width: 36, height: 36 }}>
                    {(user?.firstName || user?.username || prompt.client_name)
                        .charAt(0)
                        .toUpperCase()}
                </Avatar>

                <Box sx={{ minWidth: 0 }}>
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        Signed in as
                    </Typography>

                    <Typography variant="subtitle2" sx={{ wordBreak: "break-word" }}>
                        {user ? user.email : "your HeliumID account"}
                    </Typography>
                </Box>
            </Stack>

            <Box>
                <Typography variant="subtitle2" component="h2">
                    {prompt.client_name} will be able to:
                </Typography>

                <Stack component="ul" sx={{ listStyle: "none", m: 0, mt: 1.5, p: 0, gap: 1.5 }}>
                    {prompt.scopes.map((scope) => (
                        <Stack
                            component="li"
                            key={scope.name}
                            direction="row"
                            sx={{ gap: 1.5, alignItems: "flex-start" }}
                        >
                            <CheckCircleOutlineIcon
                                aria-hidden
                                fontSize="small"
                                color="primary"
                                sx={{ mt: 0.25, flexShrink: 0 }}
                            />

                            <Box sx={{ minWidth: 0 }}>
                                <Typography variant="body2">{scope.description}</Typography>

                                <Typography
                                    variant="caption"
                                    sx={{
                                        color: "text.secondary",
                                        fontFamily: MONO_FONT,
                                        wordBreak: "break-all",
                                    }}
                                >
                                    {scope.name}
                                </Typography>
                            </Box>
                        </Stack>
                    ))}
                </Stack>
            </Box>

            <Divider />

            <Stack
                direction={{ xs: "column-reverse", sm: "row" }}
                sx={{ gap: 1.5, alignItems: "center", justifyContent: "flex-end" }}
            >
                <Button
                    fullWidth
                    variant="text"
                    color="inherit"
                    sx={{ width: { sm: "auto" } }}
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
                    size="large"
                    variant="contained"
                    startIcon={<LockOutlinedIcon />}
                    sx={{ width: { sm: "auto" }, minWidth: { sm: 200 } }}
                    onClick={() => navigateToAuthorize(searchParams, true)}
                >
                    Allow access
                </Button>
            </Stack>

            <Typography variant="caption" sx={{ color: "text.secondary" }}>
                Your password is never shared with {prompt.client_name}. You can revoke this access
                at any time from your account settings.
            </Typography>
        </ConsentShell>
    )
}
