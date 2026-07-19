import {
    Button,
    type ButtonProps,
} from "@mui/material"
import {useAccountBox} from "../../../hooks/useAccountBox.ts";

export default function AccountButton(props: ButtonProps) {
    const {disabled} = useAccountBox()

    return (
        <Button
            {...props}
            disabled={disabled || props.disabled}
        />
    )
}