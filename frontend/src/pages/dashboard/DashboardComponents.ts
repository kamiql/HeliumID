import {
    AdminPanelSettings,
    Apps,
    GridViewOutlined,
    HistoryOutlined,
    PeopleAltOutlined,
    PersonOutlineOutlined,
    Shield,
    VpnKeyOutlined,
} from "@mui/icons-material"
import { Permissions } from "../../hooks/usePermissions.ts"

export type DashboardComponentBase = {
    name: string
    icon: typeof GridViewOutlined
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
        icon: GridViewOutlined,
        path: "/",
    },
    {
        name: "Account",
        icon: PersonOutlineOutlined,
        path: "/account",
    },
    {
        name: "Admin",
        icon: Shield,
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
                icon: AdminPanelSettings,
                path: "/admin",
            },
            {
                name: "Users",
                icon: PeopleAltOutlined,
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
                // Not the same icon as the Admin group above it: two identical marks one
                // indent apart read as the same destination.
                name: "Roles",
                icon: VpnKeyOutlined,
                path: "/admin/roles",
                require: [Permissions.ADMIN_ROLE_READ],
            },
            {
                name: "Audit log",
                icon: HistoryOutlined,
                path: "/admin/audit",
                require: [Permissions.ADMIN_AUDIT_READ],
            },
        ],
    },
]
