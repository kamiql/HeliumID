import { Alert, AlertTitle, Box, Button, Typography } from "@mui/material"
import type { SxProps, Theme } from "@mui/material/styles"
import type { ReactNode } from "react"
import { describeError, describeFieldError, ErrorCode, toHeliumError } from "../api/problem.ts"
import { humanize } from "../lib/format.ts"

type ErrorAlertProps = {
    error: unknown
    /** Hides field-level reasons when the form already renders them inline. */
    hideFieldErrors?: boolean
    /** Adds a "Try again" button. Use whenever the failed call can simply be repeated. */
    onRetry?: () => void
    retryLabel?: string
    /** Extra follow-up action, e.g. "Resend verification email". */
    action?: ReactNode
    /** Heading above the message, for a whole view failing rather than one control. */
    title?: string
    sx?: SxProps<Theme>
}

/**
 * Renders a [HeliumError] from its `code`, never from `title` or `detail`.
 *
 * `validation_failed` carries a field-to-reason map that contains no user input, so it is safe
 * to show verbatim when the form has nowhere better to put it. Field names are humanised —
 * `new_email` is wire vocabulary, not something to put in front of a user.
 */
export default function ErrorAlert({
    error,
    hideFieldErrors = false,
    onRetry,
    retryLabel = "Try again",
    action,
    title,
    sx,
}: ErrorAlertProps) {
    if (!error) return null

    const heliumError = toHeliumError(error)
    const fields = Object.entries(heliumError.fieldErrors)
    const showFields =
        !hideFieldErrors && heliumError.is(ErrorCode.VALIDATION_FAILED) && fields.length > 0
    const message = describeError(heliumError)

    return (
        <Alert
            severity="error"
            // An error that appears after the user has already acted has to be announced, not
            // just drawn.
            role="alert"
            sx={sx}
            action={
                onRetry || action ? (
                    <Box sx={{ display: "flex", gap: 0.5, alignItems: "center" }}>
                        {action}
                        {onRetry && (
                            <Button color="inherit" size="small" onClick={onRetry}>
                                {retryLabel}
                            </Button>
                        )}
                    </Box>
                ) : undefined
            }
        >
            {(title || showFields) && <AlertTitle>{title ?? message}</AlertTitle>}

            {title && <Box sx={{ mb: showFields ? 1 : 0 }}>{message}</Box>}

            {showFields && (
                <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                    {fields.map(([field, reason]) => (
                        <Typography key={field} component="li" variant="body2">
                            <Box component="strong" sx={{ fontWeight: 600 }}>
                                {humanize(field)}
                            </Box>
                            : {describeFieldError(reason)}
                        </Typography>
                    ))}
                </Box>
            )}

            {!title && !showFields && message}
        </Alert>
    )
}
