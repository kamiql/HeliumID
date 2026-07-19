import {
    Alert,
    Box,
    Card,
    CardContent,
    Divider,
    Stack,
    Typography,
} from "@mui/material"
import {
    type ReactNode
} from "react"
import type {SxProps, Theme} from "@mui/material/styles"
import type {AccountRequirement} from "./AccountRequirement.tsx"
import {AccountBoxContext} from "../../../hooks/useAccountBox.ts"

type AccountBoxProps = {
    title: string
    description: string
    requirements?: AccountRequirement[]
    sx?: SxProps<Theme>
    children: ReactNode
}

export default function AccountBox({
                                       title,
                                       description,
                                       requirements = [],
                                       sx,
                                       children,
                                   }: AccountBoxProps) {
    const disabled = requirements.some((requirement) => !requirement.satisfied)

    return (
        <AccountBoxContext.Provider value={{disabled}}>
            <Card
                sx={{
                    opacity: disabled ? 0.6 : 1,
                    filter: disabled ? "grayscale(0.25)" : "none",
                    border: disabled ? "1px solid" : undefined,
                    borderColor: disabled
                        ? "action.disabled"
                        : undefined,
                    transition: "opacity 0.2s, filter 0.2s",
                    ...sx,
                }}
            >
                <CardContent>
                    <Stack spacing={3}>
                        <Box>
                            {requirements.length > 0 && (
                                <Stack spacing={0.5}>
                                    {requirements.some((requirement) => !requirement.satisfied) && (
                                        <Stack spacing={0.5}>
                                            {requirements
                                                .filter((requirement) => !requirement.satisfied)
                                                .map((requirement) => (
                                                    <Alert
                                                        severity="error"
                                                    >
                                                        • {requirement.label}
                                                    </Alert>
                                                ))}
                                        </Stack>
                                    )}
                                </Stack>
                            )}

                            <Typography
                                variant="h6"
                                sx={{
                                    fontWeight: 600,
                                }}
                            >
                                {title}
                            </Typography>

                            <Typography
                                variant="body2"
                                sx={{
                                    mt: 0.5,
                                    color: "text.secondary",
                                }}
                            >
                                {description}
                            </Typography>
                        </Box>

                        <Divider/>

                        {children}
                    </Stack>
                </CardContent>
            </Card>
        </AccountBoxContext.Provider>
    )
}