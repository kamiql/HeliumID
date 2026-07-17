import {
    AppBar,
    Backdrop,
    Box,
    CircularProgress,
    Container,
    Toolbar,
    Typography,
} from "@mui/material"
import { Outlet } from "react-router"
import { useRequestStore } from "../../stores/request.store.ts"

export default function Layout() {
    const activeRequests = useRequestStore(
        (state) => state.activeRequests,
    )

    return (
        <Box
            sx={{
                minHeight: "100vh",
                display: "flex",
                flexDirection: "column",
            }}
        >
            <AppBar
                position="static"
                elevation={0}
                sx={{
                    background: "transparent",
                    borderBottom: "1px solid",
                    borderColor: "divider",
                }}
            >
                <Container maxWidth="lg">
                    <Toolbar
                        disableGutters
                        sx={{
                            justifyContent: "space-between",
                        }}
                    >
                        <Typography
                            sx={{
                                fontFamily: "Silkscreen, sans-serif",
                                fontSize: "1.4rem",
                                color: "text.primary",
                            }}
                        >
                            HeliumID
                        </Typography>
                    </Toolbar>
                </Container>
            </AppBar>

            <Box
                component="main"
                sx={{
                    flex: 1,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    py: 4,
                }}
            >
                <Outlet />
            </Box>

            <Backdrop
                open={activeRequests > 0}
                sx={{
                    zIndex: (theme) => theme.zIndex.modal + 1,
                    backgroundColor: "rgba(11, 15, 25, 0.65)",
                    backdropFilter: "blur(4px)",
                }}
            >
                <CircularProgress color="primary" />
            </Backdrop>
        </Box>
    )
}