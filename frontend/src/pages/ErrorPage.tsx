import { Box, Button, Container, Paper, Stack, Typography } from "@mui/material"
import { Link, isRouteErrorResponse, useRouteError } from "react-router"
import Brand from "../components/global/Brand.tsx"

/**
 * The SPA's own error screen: unknown URLs, and anything a route throws.
 *
 * The router had neither a catch-all nor an `errorElement`, so a mistyped path rendered an empty
 * shell and a thrown route error fell through to react-router's development screen — which names
 * the component that failed. This is the client-side twin of the server's `ErrorPage.kt`; the two
 * exist because a request can fail on either side of the edge, and a user cannot be expected to
 * know which side they were on.
 *
 * Deliberately offers no "try again": the reason a route threw is not visible from here, and a
 * button that fails identically the second time is worse than an honest dead end.
 */
export default function ErrorPage() {
    const error = useRouteError()

    // A 404 is the ordinary case and deserves ordinary wording; anything else is unexpected and
    // should not pretend to know what went wrong.
    const notFound = isRouteErrorResponse(error) && error.status === 404
    const unrouted = error === undefined

    const title = notFound || unrouted ? "Page not found" : "Something went wrong"
    const message =
        notFound || unrouted
            ? "That address does not match anything in this application."
            : "This page could not be displayed. The problem has been logged."

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

                            <Box sx={{ mt: 1, color: "text.secondary" }}>
                                <Typography variant="body2">{message}</Typography>
                            </Box>
                        </Box>
                    </Stack>

                    <Box>
                        <Button component={Link} to="/" variant="outlined">
                            Go to your account
                        </Button>
                    </Box>
                </Stack>
            </Paper>
        </Container>
    )
}
