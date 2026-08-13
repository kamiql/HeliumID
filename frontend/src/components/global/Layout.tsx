import { Box, LinearProgress } from "@mui/material"
import { Outlet } from "react-router"
import { useRequestStore } from "../../stores/request.store.ts"

/**
 * The root shell.
 *
 * It deliberately renders no chrome of its own: the signed-out pages get theirs from
 * [AuthLayout] and the signed-in area from `DashboardPage`, so neither ends up nested inside
 * a header meant for the other.
 *
 * The only thing that belongs at this level is the global request indicator.
 */
export default function Layout() {
    const activeRequests = useRequestStore((state) => state.activeRequests)
    const busy = activeRequests > 0

    return (
        <Box sx={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
            {/*
             * A progress bar rather than a blocking backdrop. Requests fire for background
             * reads and for every debounced filter keystroke, and freezing the whole page for
             * those made the app feel like it was constantly reloading. Forms guard against
             * double submits by disabling their own submit button while in flight.
             */}
            <Box
                aria-hidden={!busy}
                sx={{
                    position: "fixed",
                    inset: "0 0 auto 0",
                    zIndex: (theme) => theme.zIndex.tooltip + 1,
                    height: 3,
                    pointerEvents: "none",
                }}
            >
                {busy && <LinearProgress sx={{ height: 3 }} />}
            </Box>

            <Box
                role="status"
                aria-live="polite"
                className="skip-link"
                // Screen readers get the state the bar conveys visually.
                sx={{ position: "absolute" }}
            >
                {busy ? "Loading" : ""}
            </Box>

            <Outlet />
        </Box>
    )
}
