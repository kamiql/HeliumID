import {TextField, type TextFieldProps} from "@mui/material";
import {useState} from "react";

type EmailFieldProps = Omit<TextFieldProps, "type"> & {
    value: string;
    onType: (value: string) => void;
};

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function EmailField({
                                       value,
                                       onType,
                                       error,
                                       helperText,
                                       ...props
                                   }: EmailFieldProps) {
    const [touched, setTouched] = useState(false);

    const isValid = value.length === 0 || emailRegex.test(value);

    return (
        <TextField
            {...props}
            type="email"
            value={value}
            onChange={(e) => onType(e.target.value)}
            onBlur={() => setTouched(true)}
            error={error || (touched && !isValid)}
            helperText={
                helperText ??
                (touched && !isValid ? "Invalid email address" : undefined)
            }
        />
    );
}