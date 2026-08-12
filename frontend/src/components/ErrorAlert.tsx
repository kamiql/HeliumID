import { Alert, AlertTitle, Box, Typography } from "@mui/material"
import { describeError, describeFieldError, ErrorCode, toHeliumError } from "../api/problem.ts"

type ErrorAlertProps = {
    error: unknown
    /** Hides field-level reasons when the form already renders them inline. */
    hideFieldErrors?: boolean
    sx?: object
}

/**
 * Renders a [HeliumError] from its `code`, never from `title` or `detail`.
 *
 * `validation_failed` carries a field-to-reason map that contains no user input, so it is safe
 * to show verbatim when the form has nowhere better to put it.
 */
export default function ErrorAlert({ error, hideFieldErrors = false, sx }: ErrorAlertProps) {
    if (!error) return null

    const heliumError = toHeliumError(error)
    const fields = Object.entries(heliumError.fieldErrors)
    const showFields = !hideFieldErrors && heliumError.is(ErrorCode.VALIDATION_FAILED) && fields.length > 0

    return (
        <Alert severity="error" sx={sx}>
            {showFields ? (
                <>
                    <AlertTitle>{describeError(heliumError)}</AlertTitle>
                    <Box component="ul" sx={{ m: 0, pl: 2 }}>
                        {fields.map(([field, reason]) => (
                            <Typography key={field} component="li" variant="body2">
                                <strong>{field.replace(/_/g, " ")}</strong>:{" "}
                                {describeFieldError(reason)}
                            </Typography>
                        ))}
                    </Box>
                </>
            ) : (
                describeError(heliumError)
            )}
        </Alert>
    )
}
