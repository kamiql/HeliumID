import { Box, Chip, Stack, TextField, Typography } from "@mui/material"
import { useState } from "react"

type StringListFieldProps = {
    label: string
    helperText?: string
    values: string[]
    onChange: (values: string[]) => void
    placeholder?: string
    error?: boolean
}

/**
 * A chip list built from free text, used for redirect URIs and audiences.
 *
 * Both are exact-match allowlists on the server — no wildcards, no prefix matching — so each
 * entry is kept as the user typed it, with only surrounding whitespace trimmed.
 */
export default function StringListField({
    label,
    helperText,
    values,
    onChange,
    placeholder,
    error = false,
}: StringListFieldProps) {
    const [draft, setDraft] = useState("")

    const commit = () => {
        const entry = draft.trim()
        if (entry.length === 0) return
        if (!values.includes(entry)) onChange([...values, entry])
        setDraft("")
    }

    return (
        <Box>
            <TextField
                fullWidth
                size="small"
                label={label}
                value={draft}
                error={error}
                placeholder={placeholder}
                onChange={(event) => setDraft(event.target.value)}
                onBlur={commit}
                onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === ",") {
                        event.preventDefault()
                        commit()
                    }
                }}
                helperText={helperText ?? "Press Enter to add"}
            />

            {values.length > 0 && (
                <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: "wrap", gap: 1 }}>
                    {values.map((value) => (
                        <Chip
                            key={value}
                            label={value}
                            size="small"
                            onDelete={() => onChange(values.filter((item) => item !== value))}
                            sx={{ maxWidth: "100%" }}
                        />
                    ))}
                </Stack>
            )}

            {values.length === 0 && (
                <Typography variant="caption" sx={{ color: "text.secondary" }}>
                    None added yet.
                </Typography>
            )}
        </Box>
    )
}
