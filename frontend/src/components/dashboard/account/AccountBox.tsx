import { Alert, AlertTitle, Box, Link, Stack } from "@mui/material"
import { InfoOutlined } from "@mui/icons-material"
import type { ReactNode } from "react"
import type { SxProps, Theme } from "@mui/material/styles"
import Section from "../../ui/Section.tsx"
import type { AccountRequirement } from "./AccountRequirement.tsx"
import { AccountBoxContext } from "../../../hooks/useAccountBox.ts"

type AccountBoxProps = {
    title: string
    description?: string
    /** Anchor target, so a blocked box elsewhere can link here to explain how to unblock itself. */
    id?: string
    /** Preconditions. Any unmet one disables the box's controls and explains why. */
    requirements?: AccountRequirement[]
    /** Primary action for the box, rendered top-right by [Section]. */
    actions?: ReactNode
    /** Status chip or note between the heading and the body. */
    banner?: ReactNode
    tone?: "default" | "danger"
    /** The page owns `h1`, the group owns `h2`, so a box is an `h3` by default. */
    headingLevel?: "h2" | "h3" | "h4"
    disableBodyPadding?: boolean
    sx?: SxProps<Theme>
    children?: ReactNode
}

/**
 * One settings block in the account area.
 *
 * It is a thin wrapper over [Section] so the account area and the admin area share a single
 * surface language, and it adds the one thing only this area needs: requirements.
 *
 * A blocked box keeps full contrast and stays readable — dimming the whole card destroys text
 * contrast and tells assistive technology nothing. Instead the missing precondition is stated
 * in a notice, and only the controls are genuinely disabled, through [AccountBoxContext].
 */
export default function AccountBox({
    title,
    description,
    id,
    requirements = [],
    actions,
    banner,
    tone = "default",
    headingLevel = "h3",
    disableBodyPadding = false,
    sx,
    children,
}: AccountBoxProps) {
    const unmet = requirements.filter((requirement) => !requirement.satisfied)
    const disabled = unmet.length > 0

    const notice =
        unmet.length === 1 ? (
            <Alert
                severity="info"
                icon={<InfoOutlined fontSize="inherit" />}
                sx={{ alignSelf: "stretch" }}
            >
                <AlertTitle>{unmet[0].label}</AlertTitle>

                {unmet[0].hint}

                {unmet[0].fix && (
                    <Box sx={{ mt: unmet[0].hint ? 0.5 : 0 }}>
                        <Link href={`#${unmet[0].fix.anchor}`}>{unmet[0].fix.label}</Link>
                    </Box>
                )}
            </Alert>
        ) : unmet.length > 1 ? (
            // One notice with a list, rather than a stack of alerts shouting the same thing.
            <Alert
                severity="info"
                icon={<InfoOutlined fontSize="inherit" />}
                sx={{ alignSelf: "stretch" }}
            >
                <AlertTitle>Finish these first</AlertTitle>

                <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                    {unmet.map((requirement) => (
                        <Box component="li" key={requirement.id}>
                            {requirement.label}
                            {requirement.hint ? ` — ${requirement.hint}` : ""}
                            {requirement.fix && (
                                <>
                                    {" "}
                                    <Link href={`#${requirement.fix.anchor}`}>
                                        {requirement.fix.label}
                                    </Link>
                                </>
                            )}
                        </Box>
                    ))}
                </Box>
            </Alert>
        ) : null

    return (
        <AccountBoxContext.Provider value={{ disabled }}>
            <Box id={id} sx={{ minWidth: 0, height: "100%" }}>
                <Section
                    title={title}
                    description={description}
                    actions={actions}
                    headingLevel={headingLevel}
                    tone={tone}
                    disableBodyPadding={disableBodyPadding}
                    banner={
                        notice || banner ? (
                            <Stack sx={{ gap: 1.5, alignItems: "flex-start" }}>
                                {banner}
                                {notice}
                            </Stack>
                        ) : undefined
                    }
                    sx={sx}
                >
                    {children}
                </Section>
            </Box>
        </AccountBoxContext.Provider>
    )
}
