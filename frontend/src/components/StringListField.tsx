import { Box, Chip, TextField, Typography } from "@mui/material"
import { useId, useState } from "react"
import { MONO_FONT } from "../lib/theme.ts"

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

    const listId = useId()

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
                // Committing on blur as well as on Enter is deliberate: a typed-but-unadded
                // redirect URI that vanishes when the user tabs to Save is a silent data loss
                // on an allowlist that has to match exactly.
                onBlur={commit}
                onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === ",") {
                        event.preventDefault()
                        commit()
                    }
                }}
                slotProps={{ input: { sx: { fontFamily: MONO_FONT } } }}
                helperText={
                    helperText ?? "Press Enter or comma to add. Leaving the field adds it too."
                }
            />

            {/*
              * One container either way, with room for a line of chips already reserved: an
              * empty-state caption that appears and disappears shifts every field below it.
              */}
            <Box
                id={listId}
                component="ul"
                role="list"
                aria-label={`${label} entries`}
                sx={{
                    listStyle: "none",
                    m: 0,
                    mt: 1,
                    p: 0,
                    minHeight: 26,
                    display: "flex",
                    flexWrap: "wrap",
                    alignItems: "center",
                    gap: 1,
                }}
            >
                {values.length === 0 ? (
                    <Typography
                        component="li"
                        variant="caption"
                        sx={{ color: "text.secondary" }}
                    >
                        None added yet.
                    </Typography>
                ) : (
                    values.map((value) => (
                        <Chip
                            key={value}
                            component="li"
                            label={value}
                            size="small"
                            onDelete={() => onChange(values.filter((item) => item !== value))}
                            sx={{
                                maxWidth: "100%",
                                "& .MuiChip-label": { fontFamily: MONO_FONT },
                            }}
                        />
                    ))
                )}
            </Box>
        </Box>
    )
}
