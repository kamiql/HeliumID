import {
    Alert,
    Box,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    Typography,
} from "@mui/material"
import { Download } from "@mui/icons-material"
import { useState } from "react"
import CopyButton from "./CopyButton.tsx"

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

    const joined = values.join("\n")

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
            // No backdrop dismissal: an accidental click outside would destroy the only copy.
            onClose={(_event, reason) => {
                if (reason === "backdropClick" || reason === "escapeKeyDown") return
                close()
            }}
        >
            <DialogTitle>{title}</DialogTitle>

            <DialogContent>
                <Stack spacing={2}>
                    <Alert severity="warning">
                        These values are shown once. They are stored only as a hash, so we cannot
                        show them again — save them now.
                    </Alert>

                    <Typography variant="body2" sx={{ color: "text.secondary" }}>
                        {description}
                    </Typography>

                    <Box
                        sx={{
                            p: 2,
                            borderRadius: 2,
                            border: "1px solid",
                            borderColor: "divider",
                            backgroundColor: "action.hover",
                            fontFamily: "monospace",
                            fontSize: "0.9rem",
                            wordBreak: "break-all",
                            display: "grid",
                            gridTemplateColumns: values.length > 1 ? { xs: "1fr", sm: "1fr 1fr" } : "1fr",
                            gap: 1,
                        }}
                    >
                        {values.map((value) => (
                            <Box key={value}>{value}</Box>
                        ))}
                    </Box>

                    <Stack direction="row" spacing={1}>
                        <CopyButton value={joined} label="Copy all" />

                        <Button size="small" variant="outlined" startIcon={<Download />} onClick={download}>
                            Download
                        </Button>
                    </Stack>

                    {requireAcknowledgement && (
                        <Button
                            variant={acknowledged ? "contained" : "outlined"}
                            color={acknowledged ? "success" : "inherit"}
                            onClick={() => setAcknowledged(true)}
                            disabled={acknowledged}
                        >
                            {acknowledged ? "Saved" : "I have saved these somewhere safe"}
                        </Button>
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
