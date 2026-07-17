import { Box, Stack, Typography } from "@mui/material"

export default function AdminPage() {
    return (
        <Stack
            spacing={4}
            sx={{
                maxWidth: 1200,
                mx: "auto",
            }}
        >
            <Box>
                <Typography
                    variant="h4"
                    sx={{
                        fontWeight: 700,
                    }}
                >
                    Admin
                </Typography>

                <Typography
                    sx={{
                        mt: 1,
                        color: "text.secondary",
                    }}
                >
                    Administrative tools will be available here later.
                </Typography>
            </Box>
        </Stack>
    )
}