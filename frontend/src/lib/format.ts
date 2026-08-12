/** Formatting helpers for the ISO-8601 UTC timestamps the API returns. */

export function formatDateTime(value: string | null | undefined): string {
    if (!value) return "—"
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    })
}

export function formatDate(value: string | null | undefined): string {
    if (!value) return "—"
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value
    return date.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "2-digit",
    })
}

export function formatRelative(value: string | null | undefined): string {
    if (!value) return "—"
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return value

    const deltaSeconds = Math.round((date.getTime() - Date.now()) / 1000)

    const units: [Intl.RelativeTimeFormatUnit, number][] = [
        ["second", 60],
        ["minute", 60],
        ["hour", 24],
        ["day", 30],
        ["month", 12],
        ["year", Number.POSITIVE_INFINITY],
    ]

    let unitValue = deltaSeconds
    for (const [unit, size] of units) {
        if (Math.abs(unitValue) < size || unit === "year") {
            return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(
                Math.round(unitValue),
                unit,
            )
        }
        unitValue /= size
    }

    return date.toLocaleString()
}

/** Turns `USER_LOGIN_SUCCEEDED` or `user.login.succeeded` into readable prose. */
export function humanize(value: string): string {
    const spaced = value.replace(/[._-]/g, " ").toLowerCase()
    return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}
