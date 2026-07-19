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
        <>
            {boxes.map(({component: Component, props}, index) => (
                <Component
                    key={index}
                    {...props}
                />
            ))}
        </>
    )
}