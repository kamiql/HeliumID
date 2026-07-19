import {
    Button,
    Dialog,
    DialogContent,
    DialogTitle,
    Stack,
} from "@mui/material"

type MFADialogProps = {
    open: boolean
    types: string[]
    onSelect: (type: string) => void
}

export default function MFADialog({
                                      open,
                                      types,
                                      onSelect,
                                  }: MFADialogProps) {
    return (
        <Dialog
            open={open}
            fullWidth
            maxWidth="xs"
        >
            <DialogTitle>Additional verification required</DialogTitle>

            <DialogContent>
                <Stack spacing={2}>
                    {types.map((type) => (
                        <Button
                            key={type}
                            fullWidth
                            variant="outlined"
                            onClick={() => onSelect(type)}
                        >
                            {type === "EMAIL"
                                ? "Email"
                                : type === "TOTP"
                                    ? "Authenticator app"
                                    : type}
                        </Button>
                    ))}
                </Stack>
            </DialogContent>
        </Dialog>
    )
}