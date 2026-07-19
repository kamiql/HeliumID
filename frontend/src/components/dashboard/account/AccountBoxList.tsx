import {
    Box,
} from "@mui/material"
import type {ComponentType} from "react"

export type AccountBoxDefinition = {
    component: ComponentType
    props?: Record<string, unknown>
}

type AccountBoxListProps = {
    boxes: AccountBoxDefinition[]
}

export default function AccountBoxList({
    boxes,
}: AccountBoxListProps) {
    return (
        <Box
            sx={{
                width: "100%",
                minWidth: 0,
            }}
        >
            {boxes.map(({component: Component, props}, index) => (
                <Component
                    key={index}
                    {...props}
                />
            ))}
        </Box>
    )
}