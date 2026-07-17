import {Navigate, Outlet} from "react-router";
import {useUserRoles} from "../../hooks/useUserRoles.ts";

export default function RequirePermission({
                                              require,
                                              all = false,
                                          }: {
    require: string[];
    all?: boolean;
}) {
    const roles = useUserRoles();

    const permissions = roles.flatMap((role) => role.permissions);

    const hasPermission = all
        ? require.every((permission) => permissions.includes(permission))
        : require.some((permission) => permissions.includes(permission));

    if (!hasPermission) {
        return <Navigate to="/" replace/>;
    }

    return <Outlet/>;
}