import "./index.css"

import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter, RouterProvider } from "react-router"

import Layout from "./components/global/Layout.tsx"
import AuthLayout from "./components/global/AuthLayout.tsx"
import AuthProvider from "./provider/AuthProvider.tsx"
import { ConfirmProvider } from "./provider/ConfirmProvider.tsx"
import { ThemeProvider } from "./provider/ThemeProvider.tsx"

import RequireAuth from "./components/auth/RequireAuth.tsx"
import RequireGuest from "./components/auth/RequireGuest.tsx"
import RequirePermission from "./components/auth/RequirePermission.tsx"
import { Permissions } from "./hooks/usePermissions.ts"

import LoginPage from "./pages/auth/LoginPage.tsx"
import RegisterPage from "./pages/auth/RegisterPage.tsx"
import VerifyEmailPage from "./pages/auth/VerifyEmailPage.tsx"
import ConfirmEmailChangePage from "./pages/auth/ConfirmEmailChangePage.tsx"
import ForgotPasswordPage from "./pages/auth/ForgotPasswordPage.tsx"
import ResetPasswordPage from "./pages/auth/ResetPasswordPage.tsx"

import DashboardPage from "./pages/dashboard/DashboardPage.tsx"
import OverviewPage from "./pages/dashboard/overview/OverviewPage.tsx"
import AccountPage from "./pages/dashboard/account/AccountPage.tsx"
import AdminPage from "./pages/dashboard/admin/AdminPage.tsx"
import AdminUsersPage from "./pages/dashboard/admin/users/AdminUsersPage.tsx"
import AdminUserDetailPage from "./pages/dashboard/admin/users/AdminUserDetailPage.tsx"
import AdminClientsPage from "./pages/dashboard/admin/clients/AdminClientsPage.tsx"
import AdminRolesPage from "./pages/dashboard/admin/roles/AdminRolesPage.tsx"
import AdminAuditPage from "./pages/dashboard/admin/audit/AdminAuditPage.tsx"

import ConsentPage from "./pages/oauth/ConsentPage.tsx"

const ADMIN_SECTION = [
    Permissions.ADMIN_USER_READ,
    Permissions.ADMIN_CLIENT_READ,
    Permissions.ADMIN_ROLE_READ,
    Permissions.ADMIN_AUDIT_READ,
]

const router = createBrowserRouter([
    {
        path: "/",
        element: <Layout />,
        children: [
            {
                // Pathless: every page a signed-out visitor can land on shares one centred
                // card shell. It changes no URL, it only stops these pages from inheriting
                // the dashboard chrome.
                element: <AuthLayout />,
                children: [
                    {
                        // Signed-out flows. Email verification and password reset stay
                        // reachable to guests only — a signed-in user has the equivalent
                        // controls under /account.
                        element: <RequireGuest />,
                        children: [
                            { path: "login", element: <LoginPage /> },
                            { path: "register", element: <RegisterPage /> },
                            { path: "forgot-password", element: <ForgotPasswordPage /> },
                            { path: "reset-password", element: <ResetPasswordPage /> },
                        ],
                    },
                    {
                        // Not guest-only: an account pending verification can already sign in,
                        // so the link from the verification email must work while a session
                        // exists.
                        path: "verify-email",
                        element: <VerifyEmailPage />,
                    },
                    {
                        // The link is mailed to the address being claimed and may be opened in
                        // a different browser, so it must not require the session that started
                        // it.
                        path: "account/email-change/confirm",
                        element: <ConfirmEmailChangePage />,
                    },
                    {
                        // Caddy serves the SPA for this path; the page replays the query
                        // against the API and renders the consent prompt the backend returns.
                        path: "oauth2/authorize",
                        element: <ConsentPage />,
                    },
                ],
            },
            {
                element: <RequireAuth />,
                children: [
                    {
                        element: <DashboardPage />,
                        children: [
                            { index: true, element: <OverviewPage /> },
                            { path: "account", element: <AccountPage /> },
                            {
                                path: "admin",
                                element: <RequirePermission require={ADMIN_SECTION} />,
                                children: [
                                    { index: true, element: <AdminPage /> },
                                    {
                                        element: (
                                            <RequirePermission
                                                require={[Permissions.ADMIN_USER_READ]}
                                            />
                                        ),
                                        children: [
                                            { path: "users", element: <AdminUsersPage /> },
                                            {
                                                path: "users/:userId",
                                                element: <AdminUserDetailPage />,
                                            },
                                        ],
                                    },
                                    {
                                        element: (
                                            <RequirePermission
                                                require={[Permissions.ADMIN_CLIENT_READ]}
                                            />
                                        ),
                                        children: [
                                            { path: "clients", element: <AdminClientsPage /> },
                                        ],
                                    },
                                    {
                                        element: (
                                            <RequirePermission
                                                require={[Permissions.ADMIN_ROLE_READ]}
                                            />
                                        ),
                                        children: [{ path: "roles", element: <AdminRolesPage /> }],
                                    },
                                    {
                                        element: (
                                            <RequirePermission
                                                require={[Permissions.ADMIN_AUDIT_READ]}
                                            />
                                        ),
                                        children: [{ path: "audit", element: <AdminAuditPage /> }],
                                    },
                                ],
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
