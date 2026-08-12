import { api } from "./axios.ts"
import type {
    AdminUser,
    AdminUserQuery,
    AssignRolesRequest,
    AuditQuery,
    AuditRecord,
    ClientSecret,
    OAuthClient,
    Page,
    RegisterClientRequest,
    RevokeSessionsResponse,
    Role,
    Scope,
    SessionInfo,
    UpdateClientRequest,
    UpdateUserStatusRequest,
    UpsertRoleRequest,
} from "./types.ts"

/** Drops `undefined` entries so axios does not serialise them as empty query parameters. */
function params(source: Record<string, string | number | undefined>): Record<string, string | number> {
    const result: Record<string, string | number> = {}
    for (const [key, value] of Object.entries(source)) {
        if (value !== undefined && value !== "") result[key] = value
    }
    return result
}

/** `/v1/admin` — every call is permission gated server-side; the UI only hides what it can. */
export const adminApi = {
    // --- users ----------------------------------------------------------------

    users: (query: AdminUserQuery = {}) =>
        api.get<Page<AdminUser>>("/v1/admin/users", { params: params({ ...query }) }),

    user: (userId: string) => api.get<AdminUser>(`/v1/admin/users/${encodeURIComponent(userId)}`),

    updateUserStatus: (userId: string, request: UpdateUserStatusRequest) =>
        api.put<void>(`/v1/admin/users/${encodeURIComponent(userId)}/status`, request),

    assignRoles: (userId: string, request: AssignRolesRequest) =>
        api.put<void>(`/v1/admin/users/${encodeURIComponent(userId)}/roles`, request),

    userSessions: (userId: string) =>
        api.get<SessionInfo[]>(`/v1/admin/users/${encodeURIComponent(userId)}/sessions`),

    revokeUserSessions: (userId: string) =>
        api.post<RevokeSessionsResponse>(
            `/v1/admin/users/${encodeURIComponent(userId)}/revoke-sessions`,
        ),

    // --- roles and permissions ----------------------------------------------------

    roles: () => api.get<Role[]>("/v1/admin/roles"),

    permissions: () => api.get<string[]>("/v1/admin/permissions"),

    /** Built-in roles are rejected with `409 conflict` — they are referenced from code. */
    upsertRole: (name: string, request: UpsertRoleRequest) =>
        api.put<Role>(`/v1/admin/roles/${encodeURIComponent(name)}`, request),

    deleteRole: (name: string) => api.delete<void>(`/v1/admin/roles/${encodeURIComponent(name)}`),

    // --- OAuth clients ------------------------------------------------------------

    clients: (limit = 50, offset = 0) =>
        api.get<Page<OAuthClient>>("/v1/admin/clients", { params: { limit, offset } }),

    client: (clientId: string) =>
        api.get<OAuthClient>(`/v1/admin/clients/${encodeURIComponent(clientId)}`),

    scopes: () => api.get<Scope[]>("/v1/admin/scopes"),

    /** `201` with the plaintext secret. This is the only response that will ever contain it. */
    registerClient: (request: RegisterClientRequest) =>
        api.post<ClientSecret>("/v1/admin/clients", request),

    updateClient: (clientId: string, request: UpdateClientRequest) =>
        api.patch<void>(`/v1/admin/clients/${encodeURIComponent(clientId)}`, request),

    /** Also returns the plaintext exactly once; the previous secret stops working. */
    rotateClientSecret: (clientId: string) =>
        api.post<ClientSecret>(`/v1/admin/clients/${encodeURIComponent(clientId)}/rotate-secret`),

    deleteClient: (clientId: string) =>
        api.delete<void>(`/v1/admin/clients/${encodeURIComponent(clientId)}`),

    // --- audit ----------------------------------------------------------------------

    audit: (query: AuditQuery = {}) =>
        api.get<Page<AuditRecord>>("/v1/admin/audit", { params: params({ ...query }) }),
}
