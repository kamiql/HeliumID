import {AccountCircle, Dashboard, Security} from "@mui/icons-material";

export type DashboardComponentBase = {
    name: string;
    icon: typeof Dashboard;
    require?: string[];
    all?: boolean;
};

export type DashboardComponent =
    | (DashboardComponentBase & {
    path: string;
    children?: never;
})
    | (DashboardComponentBase & {
    path?: never;
    children: DashboardComponent[];
});

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
        require: ["ADMINISTRATOR"],
        children: [
            {
                name: "Overview",
                icon: Dashboard,
                path: "/admin",
            },
            {
                name: "Users",
                icon: AccountCircle,
                path: "/admin/users"
            }
        ],
    },
];