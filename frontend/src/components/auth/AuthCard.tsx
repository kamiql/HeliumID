import { Avatar, Box, Container, Paper, Typography } from "@mui/material"
import type { ReactNode } from "react"

type AuthCardProps = {
    icon: ReactNode
    title: string
    /** Palette key for the avatar, e.g. `primary.main`. */
    iconColor?: string
    children: ReactNode
}

/** The signed-out card shell: same Paper, avatar and Silkscreen heading as sign in. */
export default function AuthCard({ icon, title, iconColor = "primary.main", children }: AuthCardProps) {
    return (
        <Container component="main" maxWidth="xs">
            <Paper
                elevation={8}
                sx={{
                    p: 4,
                    width: "100%",
                    borderRadius: 3,
                    backgroundColor: "background.paper",
                }}
            >
                <Box
                    sx={{
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "center",
                    }}
                >
                    <Avatar sx={{ mb: 2, bgcolor: iconColor }}>{icon}</Avatar>

                    <Typography
                        component="h1"
                        variant="h4"
                        sx={{
                            fontFamily: "Silkscreen",
                            mb: 3,
                            textAlign: "center",
                        }}
                    >
                        {title}
                    </Typography>

                    <Box sx={{ width: "100%" }}>{children}</Box>
                </Box>
            </Paper>
        </Container>
    )
}
