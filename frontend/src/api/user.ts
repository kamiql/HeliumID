import { api } from "./axios.ts"

export type Account = {
    id: string
    email: string
    username: string
}

export type Role = {
    id: string
    name: string
    color: string
    permissions: string[]
    inherits: string[]
}

export type User = {
    id: string
    username: string
    firstName: string
    lastName: string
    email: string
    emailVerified: boolean
    totpEnabled: boolean
    linkedAccounts: Record<string, Account>
    roles: string[]
    createdAt: Date
}

export type ChangePasswordRequest = {
    old: string
    new: string
}

export type EditUserInformationRequest = {
    username: string
    firstName: string
    lastName: string
    email: string
}

export type TotpSetupResponse = {
    secret: string
    qrCode: string
}

export type TotpRequest = {
    code: string
}

export const userApi = {
    verifyEmail: () => api.post("/user/email/verify"),
    changePassword: (request: ChangePasswordRequest) =>
        api.post("/user/password/change", request),
    editPersonalInformation: (request: EditUserInformationRequest) =>
        api.post<string | null>("/user/@me", request),
    removeOauthProvider: (provider: string) => api.post(`/user/oauth2/${provider}/remove`),
    deleteAccount: () => api.post("/user/delete"),
    setupTotp: () => api.post<TotpSetupResponse>("/user/totp/setup"),
    enableTotp: (request: TotpRequest) => api.post("/user/totp/enable", request),
    disableTotp: (request: TotpRequest) => api.post("/user/totp/disable", request),
}

export const verificationApi = {
    verify: (id: string, code: string) =>
        api.post(`/verification?id=${id}&code=${code}`),
}