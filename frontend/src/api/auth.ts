import {api} from "./axios.ts";
import type {User} from "./user.ts";

export type LoginRequest = {
    email: string
    password: string
}

export type RegisterRequest = {
    username: string
    firstName: string
    lastName: string
    email: string
    password: string
}

export const authApi = {
    me: () => api.get<User>("/user/@me"),
    login: (request: LoginRequest) => api.post("/auth/login", request),
    register: (request: RegisterRequest) => api.post("/auth/register", request),
    logout: () => api.post("/auth/logout"),
    oauth: (provider: string, redirect: string | null = null) => {
        window.location.assign(`/api/auth/oauth2/${provider}/login?redirectUrl=${redirect ? redirect : window.location.pathname}`);
    }
}