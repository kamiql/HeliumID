import {
    Box,
    IconButton,
    InputAdornment,
    List,
    ListItem,
    ListItemIcon,
    TextField,
    Tooltip,
    Typography,
    type TextFieldProps,
} from "@mui/material"
import CancelIcon from "@mui/icons-material/Cancel"
import CheckCircleOutlinedIcon from "@mui/icons-material/CheckCircleOutlined"
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked"
import { Visibility, VisibilityOff } from "@mui/icons-material"
import { useState } from "react"
import { evaluatePassword, usePasswordRequirements } from "../hooks/usePasswordRequirements.ts"
import type { PasswordCheck } from "../hooks/usePasswordRequirements.ts"

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

/** `null` means only the server can decide, so the row stays neutral rather than guessing. */
function checkTone(satisfied: boolean | null): string {
    if (satisfied === null) return "text.secondary"
    return satisfied ? "success.main" : "error.main"
}

function CheckIcon({ satisfied }: { satisfied: boolean | null }) {
    if (satisfied === null) return <RadioButtonUncheckedIcon fontSize="small" />
    return satisfied ? <CheckCircleOutlinedIcon fontSize="small" /> : <CancelIcon fontSize="small" />
}

export default function PasswordField({
    value,
    onType,
    validate = false,
    matches,
    identifiers = [],
    error,
    helperText,
    fullWidth,
    ...props
}: PasswordFieldProps) {
    const [show, setShow] = useState(false)
    const [touched, setTouched] = useState(false)

    const requirements = usePasswordRequirements()
    const checks: PasswordCheck[] =
        validate && matches === undefined ? evaluatePassword(requirements, value, identifiers) : []

    const matchesValid = value === matches
    const hasError =
        touched &&
        value.length > 0 &&
        (matches !== undefined
            ? !matchesValid
            : validate && checks.some((check) => check.satisfied === false))

    const showChecklist = checks.length > 0 && value.length > 0

    return (
        <Box sx={{ width: fullWidth ? "100%" : "auto", minWidth: 0 }}>
            <TextField
                {...props}
                fullWidth={fullWidth}
                type={show ? "text" : "password"}
                value={value}
                onChange={(event) => onType(event.target.value)}
                onBlur={() => setTouched(true)}
                error={Boolean(error || hasError)}
                helperText={
                    helperText ??
                    (hasError && matches !== undefined ? "Passwords do not match" : undefined)
                }
                slotProps={{
                    input: {
                        endAdornment: (
                            <InputAdornment position="end">
                                <Tooltip title={show ? "Hide password" : "Show password"}>
                                    <IconButton
                                        aria-label={show ? "Hide password" : "Show password"}
                                        onClick={() => setShow((prev) => !prev)}
                                        edge="end"
                                    >
                                        {show ? <VisibilityOff /> : <Visibility />}
                                    </IconButton>
                                </Tooltip>
                            </InputAdornment>
                        ),
                    },
                }}
            />

            {/*
             * The checklist is announced as requirements are met, so the policy is usable
             * without seeing the colours. It is an affordance only — the server re-validates.
             */}
            <Box aria-live="polite">
                {showChecklist && (
                    <List dense disablePadding sx={{ mt: 1 }}>
                        {checks.map((check) => (
                            <ListItem
                                key={check.id}
                                disableGutters
                                disablePadding
                                sx={{ alignItems: "flex-start", py: 0.25 }}
                            >
                                <ListItemIcon
                                    sx={{
                                        minWidth: 26,
                                        mt: "1px",
                                        color: checkTone(check.satisfied),
                                    }}
                                >
                                    <CheckIcon satisfied={check.satisfied} />
                                </ListItemIcon>

                                <Typography
                                    variant="caption"
                                    sx={{ color: checkTone(check.satisfied) }}
                                >
                                    {check.label}
                                </Typography>
                            </ListItem>
                        ))}
                    </List>
                )}
            </Box>
        </Box>
    )
}
