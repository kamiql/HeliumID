import { AccountCircle, Apps, Dashboard, History, People, Security } from "@mui/icons-material"
import { Permissions } from "../../hooks/usePermissions.ts"

export type DashboardComponentBase = {
    name: string
    icon: typeof Dashboard
    /** Permission strings; the entry is hidden unless the user holds them. */
    require?: string[]
    all?: boolean
}

export type DashboardComponent =
    | (DashboardComponentBase & {
          path: string
          children?: never
      })
    | (DashboardComponentBase & {
          path?: never
          children: DashboardComponent[]
      })

export const DashboardComponents: DashboardComponent[] = [
    {
        name: "Overview",
        icon: Dashboard,
        path: "/",
    },
    {
        name: "Account",
        icon: AccountCircle,
        path: "/account",
    },
    {
        name: "Admin",
        icon: Security,
        // Any admin read permission is enough to see the section; each child gates itself.
        require: [
            Permissions.ADMIN_USER_READ,
            Permissions.ADMIN_CLIENT_READ,
            Permissions.ADMIN_ROLE_READ,
            Permissions.ADMIN_AUDIT_READ,
        ],
        children: [
            {
                name: "Overview",
                icon: Dashboard,
                path: "/admin",
            },
            {
                name: "Users",
                icon: People,
                path: "/admin/users",
                require: [Permissions.ADMIN_USER_READ],
            },
            {
                name: "Applications",
                icon: Apps,
                path: "/admin/clients",
                require: [Permissions.ADMIN_CLIENT_READ],
            },
            {
                name: "Roles",
                icon: Security,
                path: "/admin/roles",
                require: [Permissions.ADMIN_ROLE_READ],
            },
            {
                name: "Audit log",
                icon: History,
                path: "/admin/audit",
                require: [Permissions.ADMIN_AUDIT_READ],
            },
        ],
    },
]
