import {
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Divider,
    Stack,
    Typography,
} from "@mui/material"
import {type ReactNode, useState} from "react"
import {ConfirmContext} from "../hooks/useConfirm"

export type ConfirmOptions = {
    title?: string
    message: string
    confirmText?: string
    cancelText?: string
}

export function ConfirmProvider({children}: { children: ReactNode }) {
    const [options, setOptions] = useState<ConfirmOptions | null>(null)
    const [resolve, setResolve] = useState<((value: boolean) => void) | null>(null)

    const confirm = (options: ConfirmOptions) => {
        return new Promise<boolean>((resolve) => {
            setOptions(options)
            setResolve(() => resolve)
        })
    }

    const close = (result: boolean) => {
        resolve?.(result)
        setOptions(null)
        setResolve(null)
    }

    return (
        <ConfirmContext.Provider value={{confirm}}>
            {children}

            <Dialog
                open={options !== null}
                onClose={() => close(false)}
                maxWidth="xs"
                fullWidth
                slotProps={{
                    paper: {
                        sx: {
                            borderRadius: 3,
                        },
                    },
                }}
            >
                <DialogTitle sx={{pb: 1.5}}>
                    <Typography
                        variant="h6"
                        sx={{fontWeight: 700}}
                    >
                        {options?.title ?? "Confirm action"}
                    </Typography>
                </DialogTitle>

                <DialogContent sx={{pt: 0}}>
                    <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                            lineHeight: 1.6
                        }}
                    >
                        {options?.message}
                    </Typography>
                </DialogContent>

                <Divider />

                <DialogActions sx={{p: 2}}>
                    <Stack
                        direction="row"
                        spacing={1}
                        sx={{
                            width: "100%",
                            justifyContent: "flex-end"
                        }}
                    >
                        <Button
                            variant="text"
                            color="inherit"
                            onClick={() => close(false)}
                        >
                            {options?.cancelText ?? "Cancel"}
                        </Button>

                        <Button
                            variant="contained"
                            color="error"
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