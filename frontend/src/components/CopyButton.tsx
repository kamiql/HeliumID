import { Button, IconButton, Tooltip, type ButtonProps } from "@mui/material"
import { Check, ContentCopy } from "@mui/icons-material"
import { useState } from "react"

type CopyButtonProps = {
    value: string
    label?: string
    iconOnly?: boolean
    size?: ButtonProps["size"]
    variant?: ButtonProps["variant"]
}

/**
 * Copies a value to the clipboard.
 *
 * Falls back to a hidden textarea because `navigator.clipboard` is unavailable on insecure
 * origins — and a one-time secret the user cannot copy is a one-time secret they lose.
 */
export default function CopyButton({
    value,
    label = "Copy",
    iconOnly = false,
    size = "small",
    variant = "outlined",
}: CopyButtonProps) {
    const [copied, setCopied] = useState(false)

    const copy = async () => {
        try {
            if (navigator.clipboard?.writeText) {
                await navigator.clipboard.writeText(value)
            } else {
                const area = document.createElement("textarea")
                area.value = value
                area.style.position = "fixed"
                area.style.opacity = "0"
                document.body.appendChild(area)
                area.select()
                document.execCommand("copy")
                document.body.removeChild(area)
            }
            setCopied(true)
            window.setTimeout(() => setCopied(false), 1500)
        } catch {
            setCopied(false)
        }
    }

    if (iconOnly) {
        return (
            <Tooltip title={copied ? "Copied" : label}>
                <IconButton size={size} onClick={() => void copy()}>
                    {copied ? <Check fontSize="small" /> : <ContentCopy fontSize="small" />}
                </IconButton>
            </Tooltip>
        )
    }

    return (
        <Button
            size={size}
            variant={variant}
            startIcon={copied ? <Check /> : <ContentCopy />}
            onClick={() => void copy()}
        >
            {copied ? "Copied" : label}
        </Button>
    )
}
