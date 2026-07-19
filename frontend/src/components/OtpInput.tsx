import {MuiOtpInput} from "mui-one-time-password-input"

type OtpInputProps = {
    value: string
    onChange: (value: string) => void
    autoFocus?: boolean
}

export default function OtpInput({
                                     value,
                                     onChange,
                                     autoFocus = false,
                                 }: OtpInputProps) {
    return (
        <MuiOtpInput
            value={value}
            onChange={(value) => onChange(value.replace(/\D/g, "").slice(0, 6))}
            length={6}
            validateChar={(value) => /^\d$/.test(value)}
            autoFocus={autoFocus}
            TextFieldsProps={{
                inputMode: "numeric",
                autoComplete: "one-time-code",
                enterKeyHint: "done",
                sx: {
                    "& .MuiInputBase-root": {
                        width: "100%",
                    },
                },
                slotProps: {
                    htmlInput: {
                        inputMode: "numeric",
                        pattern: "[0-9]*",
                        autoComplete: "one-time-code",
                        enterKeyHint: "done",
                    },
                },
            }}
            sx={{
                gap: {
                    xs: 0.5,
                    sm: 1,
                },
                width: "100%",
            }}
        />
    )
}