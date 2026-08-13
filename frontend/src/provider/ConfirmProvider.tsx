import {
    Box,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Divider,
    Stack,
} from "@mui/material"
import { WarningAmberRounded } from "@mui/icons-material"
import { type ReactNode, useId, useState } from "react"
import { ConfirmContext } from "../hooks/useConfirm.ts"

export type ConfirmOptions = {
    title?: string
    message: string
    confirmText?: string
    cancelText?: string
    /**
     * Picks the weight of the prompt.
     *
     * `"danger"` (the default) is for anything that destroys or revokes state — the confirm
     * button turns red, a warning icon backs the colour up for anyone who cannot see it, and
     * focus starts on Cancel so a stray Enter cannot delete something. `"default"` is for a
     * merely deliberate action such as signing out: neutral primary button, no warning, and
     * focus starts on the confirm button because that is the expected answer.
     */
    tone?: "danger" | "default"
}

/**
 * The one confirmation prompt in the app.
 *
 * A promise-returning `confirm()` keeps call sites linear (`if (!confirmed) return`) instead of
 * threading dialog state through every page that can delete something.
 */
export function ConfirmProvider({ children }: { children: ReactNode }) {
    const [options, setOptions] = useState<ConfirmOptions | null>(null)
    const [open, setOpen] = useState(false)
    const [resolve, setResolve] = useState<((value: boolean) => void) | null>(null)

    const titleId = useId()
    const messageId = useId()

    const confirm = (next: ConfirmOptions) => {
        return new Promise<boolean>((settle) => {
            // A second prompt raised while one is still open would strand the first promise
            // forever, so the one being replaced resolves as "declined".
            resolve?.(false)
            setResolve(() => settle)
            setOptions(next)
            setOpen(true)
        })
    }

    const close = (result: boolean) => {
        resolve?.(result)
        setResolve(null)
        setOpen(false)
    }

    const danger = (options?.tone ?? "danger") === "danger"

    return (
        <ConfirmContext.Provider value={{ confirm }}>
            {children}

            <Dialog
                open={open}
                onClose={() => close(false)}
                maxWidth="xs"
                fullWidth
                aria-labelledby={titleId}
                aria-describedby={messageId}
                // The options survive the closing transition so the prompt does not flash back
                // to its placeholder copy on its way out.
                slotProps={{
                    transition: {
                        onExited: () => setOptions(null),
                    },
                }}
            >
                <DialogTitle id={titleId} sx={{ pb: 1.5 }}>
                    <Stack direction="row" spacing={1.25} sx={{ alignItems: "flex-start" }}>
                        {danger && (
                            // Colour is never the only signal: the icon says "destructive" on a
                            // greyscale screen too.
                            <Box
                                aria-hidden
                                sx={{
                                    display: "flex",
                                    color: "error.main",
                                    mt: "1px",
                                }}
                            >
                                <WarningAmberRounded fontSize="small" />
                            </Box>
                        )}

                        <Box component="span" sx={{ fontWeight: 700 }}>
                            {options?.title ?? "Confirm action"}
                        </Box>
                    </Stack>
                </DialogTitle>

                <DialogContent sx={{ pt: 0 }}>
                    <DialogContentText id={messageId} variant="body2" sx={{ lineHeight: 1.6 }}>
                        {options?.message}
                        {danger && (
                            <Box component="span" sx={{ display: "block", mt: 1 }}>
                                This takes effect immediately.
                            </Box>
                        )}
                    </DialogContentText>
                </DialogContent>

                <Divider />

                <DialogActions sx={{ p: 2 }}>
                    <Stack
                        direction={{ xs: "column-reverse", sm: "row" }}
                        spacing={1}
                        sx={{
                            width: "100%",
                            justifyContent: { sm: "flex-end" },
                        }}
                    >
                        <Button
                            variant="text"
                            color="inherit"
                            // A destructive prompt opens on Cancel: the safe answer should be
                            // the one a reflexive Enter or Space produces.
                            autoFocus={danger}
                            onClick={() => close(false)}
                        >
                            {options?.cancelText ?? "Cancel"}
                        </Button>

                        <Button
                            variant="contained"
                            color={danger ? "error" : "primary"}
                            autoFocus={!danger}
                            onClick={() => close(true)}
                        >
                            {options?.confirmText ?? "Confirm"}
                        </Button>
                    </Stack>
                </DialogActions>
            </Dialog>
        </ConfirmContext.Provider>
    )
}
