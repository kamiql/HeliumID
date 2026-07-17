import axios from "axios"
import { useRequestStore } from "../stores/request.store.ts"

export const api = axios.create({
    baseURL: "/api",
    withCredentials: true,
})

api.interceptors.request.use(
    (config) => {
        useRequestStore.getState().startRequest()

        return config
    },
    (error) => {
        useRequestStore.getState().finishRequest()

        return Promise.reject(error)
    },
)

api.interceptors.response.use(
    (response) => {
        useRequestStore.getState().finishRequest()

        return response
    },
    (error) => {
        useRequestStore.getState().finishRequest()

        return Promise.reject(error)
    },
)