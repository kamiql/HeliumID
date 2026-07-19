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
            onChange={(value) => {
                onChange(value.replace(/\D/g, "").slice(0, 6))
            }}
            length={6}
            validateChar={(value) => /^\d$/.test(value)}
            autoFocus={autoFocus}
            TextFieldsProps={{
                type: "text",
                inputProps: {
                    inputMode: "numeric",
                    pattern: "[0-9]*",
                },
            }}
        />
    )
}