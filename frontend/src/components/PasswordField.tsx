import {
    IconButton,
    InputAdornment,
    TextField,
    Typography,
    Box,
    type TextFieldProps
} from "@mui/material";
import {Visibility, VisibilityOff} from "@mui/icons-material";
import {useState} from "react";
import {usePasswordRequirements} from "../hooks/usePasswordRequirements.ts";

type PasswordFieldProps = Omit<TextFieldProps, "type" | "onChange"> & {
    value: string;
    onType: (value: string) => void;
    validate?: boolean;
    matches?: string;
};

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

    const requirements = usePasswordRequirements();
    const matchesValid = value === matches;

    const hasError = validate && touched && value.length > 0 && (
        matches !== undefined
            ? !matchesValid
            : requirements !== null && Object.values(requirements).some(
            (requirement) => !new RegExp(requirement.regex).test(value)
        )
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
                    validate && matches === undefined && value.length > 0 && requirements !== null ? (
                        <Box sx={{mt: 1}}>
                            {Object.entries(requirements).map(([key, requirement]) => {
                                const valid = new RegExp(requirement.regex).test(value);

                                return (
                                    <Typography
                                        key={key}
                                        variant="body2"
                                        sx={{
                                            color: valid ? "success.main" : "error.main",
                                            display: "flex",
                                            alignItems: "center",
                                            gap: 0.5
                                        }}
                                    >
                                        {valid ? "✓" : "✕"} {requirement.description}
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
                                {show ? <VisibilityOff/> : <Visibility/>}
                            </IconButton>
                        </InputAdornment>
                    )
                }
            }}
        />
    );
}