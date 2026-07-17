import { useMemo } from "react"
import { useUser } from "./useUser.ts"
import {useRoleStore} from "../stores/role.store.ts";

export function useUserRoles() {
    const user = useUser()
    const roles = useRoleStore((state) => state.roles)

    return useMemo(
        () => roles.filter((role) => user?.roles?.includes(role.id) ?? false),
        [roles, user?.roles],
    )
}