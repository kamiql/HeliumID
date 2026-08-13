import { Box, Container, Stack, Typography } from "@mui/material"
import { Outlet } from "react-router"
import ThemeToggle from "./ThemeToggle.tsx"

/**
 * The shell for every page a signed-out visitor can reach: sign in, sign up, the mailed
 * verification and reset links, and the OAuth consent prompt.
 *
 * One column, one card, nothing competing with it. The wordmark stays at the top so a user
 * who arrived from a relying party can see whose credentials they are about to type.
 */
export default function AuthLayout() {
    return (
        <Box
            sx={{
                flex: 1,
                display: "flex",
                flexDirection: "column",
                minHeight: "100vh",
            }}
        >
            {/*
             * No wordmark here: the card below already leads with it, and two marks on one
             * screen make the page look like a frame around another site.
             */}
            <Box
                component="header"
                sx={{
                    px: { xs: 2, sm: 3 },
                    py: 2,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "flex-end",
                }}
            >
                <ThemeToggle size="small" />
            </Box>

            <Container
                component="main"
                maxWidth={false}
                sx={{
                    flex: 1,
                    display: "flex",
                    // Top-aligned with breathing room rather than dead-centred: a tall form
                    // (register step two, the consent scope list) would otherwise push its own
                    // heading off the top of a short viewport.
                    alignItems: { xs: "flex-start", sm: "center" },
                    justifyContent: "center",
                    px: { xs: 2, sm: 3 },
                    py: { xs: 2, sm: 5 },
                }}
            >
                <Outlet />
            </Container>

            <Box
                component="footer"
                sx={{
                    px: { xs: 2, sm: 3 },
                    py: 2.5,
                    borderTop: "1px solid",
                    borderColor: "divider",
                }}
            >
                <Stack
                    direction="row"
                    sx={{ gap: 1, justifyContent: "center", flexWrap: "wrap" }}
                >
                    <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        Secured by HeliumID
                    </Typography>
                </Stack>
            </Box>
        </Box>
    )
}
