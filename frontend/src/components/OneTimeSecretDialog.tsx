import {
    Alert,
    AlertTitle,
    Box,
    Button,
    Checkbox,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    FormControlLabel,
    Stack,
} from "@mui/material"
import { Download } from "@mui/icons-material"
import { useId, useState } from "react"
import CopyButton from "./CopyButton.tsx"
import { MONO_FONT } from "../lib/theme.ts"

type OneTimeSecretDialogProps = {
    open: boolean
    title: string
    description: string
    /** One entry per line. A client secret is a single line; recovery codes are many. */
    values: string[]
    downloadFileName: string
    /** Forces an explicit acknowledgement before the dialog can be dismissed. */
    requireAcknowledgement?: boolean
    onClose: () => void
}

/**
 * Displays a secret the server will never show again.
 *
 * Client secrets and recovery codes are stored only as hashes, so there is no endpoint that
 * could re-reveal them — losing this dialog means rotating or regenerating. That is why the
 * warning is loud and why dismissal is gated behind an explicit acknowledgement.
 */
export default function OneTimeSecretDialog({
    open,
    title,
    description,
    values,
    downloadFileName,
    requireAcknowledgement = true,
    onClose,
}: OneTimeSecretDialogProps) {
    const [acknowledged, setAcknowledged] = useState(false)

    const titleId = useId()
    const descriptionId = useId()

    const joined = values.join("\n")
    const many = values.length > 1

    const download = () => {
        const blob = new Blob([`${joined}\n`], { type: "text/plain;charset=utf-8" })
        const url = URL.createObjectURL(blob)
        const anchor = document.createElement("a")
        anchor.href = url
        anchor.download = downloadFileName
        anchor.click()
        URL.revokeObjectURL(url)
    }

    const close = () => {
        setAcknowledged(false)
        onClose()
    }

    return (
        <Dialog
            open={open}
            fullWidth
            maxWidth="sm"
            aria-labelledby={titleId}
            aria-describedby={descriptionId}
            // No backdrop dismissal: an accidental click outside would destroy the only copy.
            onClose={(_event, reason) => {
                if (reason === "backdropClick" || reason === "escapeKeyDown") return
                close()
            }}
        >
            <DialogTitle id={titleId}>{title}</DialogTitle>

            <DialogContent>
                <Stack spacing={2}>
                    <Alert severity="warning">
                        <AlertTitle>Shown once</AlertTitle>
                        These values are stored only as a hash, so we cannot show them again —
                        save them now.
                    </Alert>

                    <DialogContentText id={descriptionId} variant="body2">
                        {description}
                    </DialogContentText>

                    <Box
                        component={many ? "ol" : "div"}
                        // `list-style: none` drops list semantics in some browsers; the role
                        // puts them back so the count is still announced.
                        role={many ? "list" : undefined}
                        aria-label={many ? "Generated values" : undefined}
                        sx={{
                            listStyle: "none",
                            m: 0,
                            p: 1,
                            borderRadius: 2,
                            border: "1px solid",
                            borderColor: "divider",
                            backgroundColor: "action.hover",
                            display: "grid",
                            // One column on a phone: a two-up grid of long values wraps into
                            // an unreadable block at 360px.
                            gridTemplateColumns: many ? { xs: "1fr", sm: "1fr 1fr" } : "1fr",
                            gap: 0.5,
                        }}
                    >
                        {values.map((value) => (
                            <Box
                                key={value}
                                component={many ? "li" : "div"}
                                sx={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 1,
                                    minWidth: 0,
                                    px: 1,
                                    py: 0.5,
                                    borderRadius: 1.5,
                                }}
                            >
                                <Box
                                    component="span"
                                    sx={{
                                        flex: 1,
                                        minWidth: 0,
                                        fontFamily: MONO_FONT,
                                        fontSize: "0.8125rem",
                                        lineHeight: 1.6,
                                        // Secrets have no word boundaries, so they have to be
                                        // allowed to break mid-token rather than overflow.
                                        wordBreak: "break-all",
                                        color: "text.primary",
                                    }}
                                >
                                    {value}
                                </Box>

                                {/*
                                  * A per-entry copy button only earns its place in a list:
                                  * with a single value, "Copy all" below already does it.
                                  */}
                                {many && <CopyButton value={value} label="Copy code" iconOnly />}
                            </Box>
                        ))}
                    </Box>

                    <Stack
                        direction={{ xs: "column", sm: "row" }}
                        spacing={1}
                        sx={{ alignItems: { xs: "stretch", sm: "center" } }}
                    >
                        <CopyButton value={joined} label="Copy all" />

                        <Button
                            size="small"
                            variant="outlined"
                            startIcon={<Download />}
                            onClick={download}
                        >
                            Download
                        </Button>
                    </Stack>

                    {requireAcknowledgement && (
                        <FormControlLabel
                            sx={{ mr: 0, alignItems: "flex-start" }}
                            control={
                                <Checkbox
                                    checked={acknowledged}
                                    onChange={(event) => setAcknowledged(event.target.checked)}
                                    sx={{ pt: 0.25 }}
                                />
                            }
                            label="I have saved these somewhere safe"
                        />
                    )}
                </Stack>
            </DialogContent>

            <DialogActions>
                <Button
                    variant="contained"
                    onClick={close}
                    disabled={requireAcknowledgement && !acknowledged}
                >
                    Done
                </Button>
            </DialogActions>
        </Dialog>
    )
}
