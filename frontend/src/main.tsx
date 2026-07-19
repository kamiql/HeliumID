import "./index.css"

import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import {
    createBrowserRouter,
    RouterProvider,
} from "react-router"

import Layout from "./components/global/Layout.tsx"
import AuthProvider from "./provider/AuthProvider.tsx"
import RequireAuth from "./components/auth/RequireAuth.tsx"

import RegisterPage from "./pages/auth/RegisterPage.tsx"
import LoginPage from "./pages/auth/LoginPage.tsx"
import RequireGuest from "./components/auth/RequireGuest.tsx"
import DashboardPage from "./pages/dashboard/DashboardPage.tsx";
import AccountPage from "./pages/dashboard/account/AccountPage.tsx";
import AdminPage from "./pages/dashboard/admin/AdminPage.tsx";
import OverviewPage from "./pages/dashboard/overview/OverviewPage.tsx";
import {ConfirmProvider} from "./provider/ConfirmProvider.tsx";
import RequirePermission from "./components/auth/RequirePermission.tsx";
import { ThemeProvider } from "./provider/ThemeProvider.tsx"

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
                                element: <RequirePermission require={["ADMINISTRATOR"]}/>,
                                children: [
                                    {
                                        index: true,
                                        element: <AdminPage/>
                                    },
                                    {
                                        path: "users",
                                        element: <></>
                                    }
                                ]
                            },
                        ],
                    },
                ],
            },
        ],
    },
])

createRoot(document.getElementById("root")!).render(
    <StrictMode>
        <ThemeProvider>
            <ConfirmProvider>
                <AuthProvider>
                    <RouterProvider router={router} />
                </AuthProvider>
            </ConfirmProvider>
        </ThemeProvider>
    </StrictMode>,
)