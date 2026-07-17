import {
    IconButton,
    InputAdornment,
    TextField,
    Typography,
    Box,
    type TextFieldProps
} from "@mui/material";
import { Visibility, VisibilityOff } from "@mui/icons-material";
import { useState } from "react";

type PasswordFieldProps = Omit<TextFieldProps, "type" | "onChange"> & {
    value: string;
    onType: (value: string) => void;
    validate?: boolean;
    matches?: string;
};

const requirements = [
    {
        label: "8-32 characters",
        test: (value: string) => value.length >= 8 && value.length <= 32
    },
    {
        label: "One uppercase letter",
        test: (value: string) => /[A-Z]/.test(value)
    },
    {
        label: "One lowercase letter",
        test: (value: string) => /[a-z]/.test(value)
    },
    {
        label: "One number",
        test: (value: string) => /[0-9]/.test(value)
    },
    {
        label: "One special character",
        test: (value: string) => /[^A-Za-z0-9]/.test(value)
    }
];

export default function PasswordField({
                                          value,
                                          onType,
                                          validate = false,
                                          matches,
                                          error,
                                          helperText,
                                          ...props
                                      }: PasswordFieldProps) {
    const [show, setShow] = useState(false);
    const [touched, setTouched] = useState(false);

    const matchesValid = value === matches;

    const hasError = validate && touched && value.length > 0 && (
        matches !== undefined
            ? !matchesValid
            : requirements.some((req) => !req.test(value))
    );

    return (
        <TextField
            {...props}
            type={show ? "text" : "password"}
            value={value}
            onChange={(e) => onType(e.target.value)}
            onBlur={() => setTouched(true)}
            error={Boolean(error || hasError)}
            helperText={
                helperText ??
                (
                    validate && matches === undefined && value.length > 0 ? (
                        <Box sx={{ mt: 1 }}>
                            {requirements.map((req) => {
                                const valid = req.test(value);

                                return (
                                    <Typography
                                        key={req.label}
                                        variant="body2"
                                        sx={{
                                            color: valid ? "success.main" : "error.main",
                                            display: "flex",
                                            alignItems: "center",
                                            gap: 0.5
                                        }}
                                    >
                                        {valid ? "✓" : "✕"} {req.label}
                                    </Typography>
                                );
                            })}
                        </Box>
                    ) : hasError && matches !== undefined ? (
                        "Passwords do not match"
                    ) : undefined
                )
            }
            slotProps={{
                input: {
                    endAdornment: (
                        <InputAdornment position="end">
                            <IconButton
                                onClick={() => setShow((prev) => !prev)}
                                edge="end"
                            >
                                {show ? <VisibilityOff /> : <Visibility />}
                            </IconButton>
                        </InputAdornment>
                    )
                }
            }}
        />
    );
}