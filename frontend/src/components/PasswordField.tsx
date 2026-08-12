import {
    Box,
    IconButton,
    InputAdornment,
    TextField,
    Typography,
    type TextFieldProps,
} from "@mui/material"
import { Visibility, VisibilityOff } from "@mui/icons-material"
import { useState } from "react"
import { evaluatePassword, usePasswordRequirements } from "../hooks/usePasswordRequirements.ts"

type PasswordFieldProps = Omit<TextFieldProps, "type" | "onChange"> & {
    value: string
    onType: (value: string) => void
    /** Renders the live policy checklist below the field. */
    validate?: boolean
    /** When set, the field becomes a confirmation field for this value. */
    matches?: string
    /** Username/email, so "must not contain your identifier" can be previewed locally. */
    identifiers?: string[]
}

export default function PasswordField({
    value,
    onType,
    validate = false,
    matches,
    identifiers = [],
    error,
    helperText,
    ...props
}: PasswordFieldProps) {
    const [show, setShow] = useState(false)
    const [touched, setTouched] = useState(false)

    const requirements = usePasswordRequirements()
    const checks =
        validate && matches === undefined ? evaluatePassword(requirements, value, identifiers) : []

    const matchesValid = value === matches
    const hasError =
        touched &&
        value.length > 0 &&
        (matches !== undefined
            ? !matchesValid
            : validate && checks.some((check) => check.satisfied === false))

    return (
        <TextField
            {...props}
            type={show ? "text" : "password"}
            value={value}
            onChange={(event) => onType(event.target.value)}
            onBlur={() => setTouched(true)}
            error={Boolean(error || hasError)}
            helperText={
                helperText ??
                (checks.length > 0 && value.length > 0 ? (
                    <Box sx={{ mt: 1 }}>
                        {checks.map((check) => (
                            <Typography
                                key={check.id}
                                variant="body2"
                                component="span"
                                sx={{
                                    color:
                                        check.satisfied === null
                                            ? "text.secondary"
                                            : check.satisfied
                                              ? "success.main"
                                              : "error.main",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 0.5,
                                }}
                            >
                                {check.satisfied === null ? "•" : check.satisfied ? "✓" : "✕"}{" "}
                                {check.label}
                            </Typography>
                        ))}
                    </Box>
                ) : hasError && matches !== undefined ? (
                    "Passwords do not match"
                ) : undefined)
            }
            slotProps={{
                input: {
                    endAdornment: (
                        <InputAdornment position="end">
                            <IconButton onClick={() => setShow((prev) => !prev)} edge="end">
                                {show ? <VisibilityOff /> : <Visibility />}
                            </IconButton>
                        </InputAdornment>
                    ),
                },
            }}
        />
    )
}
