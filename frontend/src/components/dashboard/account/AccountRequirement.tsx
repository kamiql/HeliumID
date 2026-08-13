/**
 * A precondition a box needs before its controls do anything.
 *
 * An unmet requirement is never a dead end: it carries the sentence that explains what is
 * missing and, where another box can satisfy it, a link straight to that box.
 */
export type AccountRequirement = {
    id: string
    /** What is missing, phrased as the thing to do: "Verify your email address first". */
    label: string
    /** Why this box needs it. One sentence, no jargon. */
    hint?: string
    /** Jump to the box that satisfies the requirement. */
    fix?: {
        label: string
        /** Anchor id of the target box — one of [ACCOUNT_ANCHORS]. */
        anchor: string
    }
    satisfied: boolean
}

/**
 * Anchor ids for the boxes other boxes point at.
 *
 * Requirements are cross-cutting — the password box is blocked by the email box — so the ids
 * live in one place rather than being spelled out as strings in both.
 */
export const ACCOUNT_ANCHORS = {
    email: "account-email",
    totp: "account-two-factor",
    passkeys: "account-passkeys",
} as const
