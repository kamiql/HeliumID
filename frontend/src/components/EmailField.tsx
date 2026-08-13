import { TextField, type TextFieldProps } from "@mui/material"
import { useState } from "react"

type EmailFieldProps = Omit<TextFieldProps, "type"> & {
    value: string
    onType: (value: string) => void
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/** Keeps the helper row in the layout even when there is nothing to say. */
const RESERVED_HELPER = " "

export default function EmailField({ value, onType, error, helperText, ...props }: EmailFieldProps) {
    const [touched, setTouched] = useState(false)

    const isValid = value.length === 0 || emailRegex.test(value)

    return (
        <TextField
            {...props}
            type="email"
            value={value}
            onChange={(e) => onType(e.target.value)}
            onBlur={() => setTouched(true)}
            error={error || (touched && !isValid)}
            // The helper slot is always rendered: the field must not shove the rest of the form
            // down the moment the address goes invalid.
            helperText={
                helperText ?? (touched && !isValid ? "Invalid email address" : RESERVED_HELPER)
            }
        />
    )
}
