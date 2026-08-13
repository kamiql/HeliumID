import { MuiOtpInput } from "mui-one-time-password-input"

type OtpInputProps = {
    value: string
    onChange: (value: string) => void
    autoFocus?: boolean
}

/**
 * Six single-character boxes for a TOTP or enrollment code.
 *
 * Everything non-numeric is stripped on the way in, so a pasted code that carries a space or a
 * dash still lands correctly instead of being silently rejected character by character.
 */
export default function OtpInput({ value, onChange, autoFocus = false }: OtpInputProps) {
    return (
        <MuiOtpInput
            value={value}
            onChange={(next) => onChange(next.replace(/\D/g, "").slice(0, 6))}
            length={6}
            validateChar={(character) => /^\d$/.test(character)}
            autoFocus={autoFocus}
            TextFieldsProps={{
                // These belong on the `input` element, not on the field wrapper: they are what
                // brings up the numeric keypad and lets the OS offer the SMS/TOTP autofill.
                // `autoComplete="one-time-code"` is already set on every box by the library.
                slotProps: {
                    htmlInput: {
                        inputMode: "numeric",
                        pattern: "[0-9]*",
                        enterKeyHint: "done",
                        "aria-label": "Digit",
                    },
                },
            }}
            sx={{
                width: "100%",
                gap: { xs: 0.5, sm: 1 },
                // Six equal boxes that shrink with the dialog — at 360px a fixed width would
                // push the last digit off the edge.
                "& .MuiOtpInput-TextField": { flex: 1, minWidth: 0 },
                "& .MuiInputBase-root": { width: "100%" },
                "& .MuiInputBase-input": {
                    px: 0,
                    textAlign: "center",
                    fontSize: { xs: "1rem", sm: "1.125rem" },
                },
            }}
        />
    )
}
