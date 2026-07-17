import "./index.css"

import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import {
    createBrowserRouter,
    RouterProvider,
} from "react-router"
import {
    createTheme,
    CssBaseline,
    ThemeProvider,
} from "@mui/material"

import Layout from "./components/global/Layout.tsx"
import AuthProvider from "./components/auth/AuthProvider.tsx"
import RequireAuth from "./components/auth/RequireAuth.tsx"

import RegisterPage from "./pages/auth/RegisterPage.tsx"
import LoginPage from "./pages/auth/LoginPage.tsx"
import RequireGuest from "./components/auth/RequireGuest.tsx"
import DashboardPage from "./pages/dashboard/DashboardPage.tsx";
import AccountPage from "./pages/dashboard/account/AccountPage.tsx";
import AdminPage from "./pages/dashboard/admin/AdminPage.tsx";
import OverviewPage from "./pages/dashboard/overview/OverviewPage.tsx";
import VerifyPage from "./pages/verification/VerifyPage.tsx";
import {ConfirmProvider} from "./components/Confirm.tsx";

const router = createBrowserRouter([
    {
        path: "/",
        element: <Layout />,
        children: [
            {
                element: <RequireGuest />,
                children: [
                    {
                        path: "login",
                        element: <LoginPage />,
                    },
                    {
                        path: "register",
                        element: <RegisterPage />,
                    },
                ],
            },
            {
                path: "verification",
                element: <VerifyPage/>
            },
            {
                element: <RequireAuth />,
                children: [
                    {
                        element: <DashboardPage />,
                        children: [
                            {
                                index: true,
                                element: <OverviewPage />,
                            },
                            {
                                path: "account",
                                element: <AccountPage />,
                            },
                            {
                                path: "admin",
                                element: <AdminPage />,
                            },
                        ],
                    },
                ],
            },
        ],
    },
])

const theme = createTheme({
    palette: {
        mode: "dark",
        primary: {
            main: "#5865F2",
            light: "#7983F5",
            dark: "#4752C4",
            contrastText: "#ffffff",
        },
        secondary: {
            main: "#3B82F6",
            light: "#60A5FA",
            dark: "#2563EB",
            contrastText: "#ffffff",
        },
        background: {
            default: "#0b0f19",
            paper: "#111827",
        },
        text: {
            primary: "#f8fafc",
            secondary: "#94a3b8",
        },
        divider: "#1e293b",
        success: {
            main: "#22c55e",
        },
        error: {
            main: "#ef4444",
        },
        warning: {
            main: "#f59e0b",
        },
        info: {
            main: "#38bdf8",
        },
    },
})

createRoot(document.getElementById("root")!).render(
    <StrictMode>
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <ConfirmProvider>
                <AuthProvider>
                    <RouterProvider router={router} />
                </AuthProvider>
            </ConfirmProvider>
        </ThemeProvider>
    </StrictMode>,
)