import { useEffect, useState } from "react"
import { authApi } from "../api/auth.ts"
import type { PasswordRequirements } from "../api/types.ts"

/**
 * The password policy, fetched from `GET /v1/auth/password-requirements`.
 *
 * The policy is published so the UI can show a live checklist instead of guessing, but the
 * server re-validates everything: this is a usability affordance, never an enforcement point.
 */

let cache: PasswordRequirements | null = null
let inFlight: Promise<PasswordRequirements | null> | null = null

function load(): Promise<PasswordRequirements | null> {
    if (cache) return Promise.resolve(cache)
    if (inFlight) return inFlight

    inFlight = authApi
        .passwordRequirements()
        .then(({ data }) => {
            cache = data
            return data
        })
        .catch(() => null)
        .finally(() => {
            inFlight = null
        })

    return inFlight
}

export function usePasswordRequirements(): PasswordRequirements | null {
    const [requirements, setRequirements] = useState<PasswordRequirements | null>(cache)

    useEffect(() => {
        let active = true
        void load().then((loaded) => {
            if (active && loaded) setRequirements(loaded)
        })
        return () => {
            active = false
        }
    }, [])

    return requirements
}

export type PasswordCheck = {
    id: string
    label: string
    /** `null` when only the server can decide (a breach lookup, for example). */
    satisfied: boolean | null
}

/**
 * Turns the policy into a checklist for the given candidate password.
 *
 * @param identifiers username and email, so the "must not contain your identifier" rule can be
 *        previewed locally. The authoritative check still happens server-side.
 */
export function evaluatePassword(
    requirements: PasswordRequirements | null,
    password: string,
    identifiers: string[] = [],
): PasswordCheck[] {
    if (!requirements) return []

    const checks: PasswordCheck[] = [
        {
            id: "min_length",
            label: `At least ${requirements.min_length} characters`,
            satisfied: password.length >= requirements.min_length,
        },
    ]

    if (requirements.max_length > 0 && requirements.max_length < 4096) {
        checks.push({
            id: "max_length",
            label: `At most ${requirements.max_length} characters`,
            satisfied: password.length <= requirements.max_length,
        })
    }

    if (requirements.rejects_identifier) {
        const lowered = password.toLowerCase()
        const candidates = identifiers
            .map((value) => value.trim().toLowerCase())
            .filter((value) => value.length >= 3)

        checks.push({
            id: "rejects_identifier",
            label: "Does not contain your username or email",
            satisfied: candidates.every((value) => !lowered.includes(value)),
        })
    }

    if (requirements.breached_check) {
        checks.push({
            id: "breached_check",
            label: "Checked against known breached passwords",
            // Deliberately unresolved: the lookup happens on the server and the UI must not
            // pretend to know the answer.
            satisfied: null,
        })
    }

    return checks
}
