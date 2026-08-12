import { useEffect, useState } from "react"
import { authApi } from "../api/auth.ts"

/** The external identity providers this deployment offers, cached for the session. */
let cache: string[] | null = null
let inFlight: Promise<string[]> | null = null

function load(): Promise<string[]> {
    if (cache) return Promise.resolve(cache)
    if (inFlight) return inFlight

    inFlight = authApi
        .providers()
        .then(({ data }) => {
            cache = data.providers
            return cache
        })
        .catch(() => [])
        .finally(() => {
            inFlight = null
        })

    return inFlight
}

export function useProviders(): string[] {
    const [providers, setProviders] = useState<string[]>(cache ?? [])

    useEffect(() => {
        let active = true
        void load().then((loaded) => {
            if (active) setProviders(loaded)
        })
        return () => {
            active = false
        }
    }, [])

    return providers
}
