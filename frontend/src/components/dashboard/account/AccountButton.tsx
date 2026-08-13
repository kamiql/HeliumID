import { Button, type ButtonProps } from "@mui/material"
import { useAccountBox } from "../../../hooks/useAccountBox.ts"

/**
 * A button that knows whether its box is blocked.
 *
 * The disabled state comes from [AccountBoxContext] rather than from a prop threaded through
 * every box, so a control can never stay live while the notice above it says the box is not
 * available yet.
 */
export default function AccountButton(props: ButtonProps) {
    const { disabled } = useAccountBox()

    return <Button {...props} disabled={disabled || props.disabled} />
}
