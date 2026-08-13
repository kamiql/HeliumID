import { Check, DarkModeOutlined, LightModeOutlined, SettingsBrightness } from "@mui/icons-material"
import {
    IconButton,
    ListItemIcon,
    ListItemText,
    Menu,
    MenuItem,
    Tooltip,
    type SvgIconProps,
} from "@mui/material"
import { useState, type ComponentType, type MouseEvent } from "react"
import { useTheme, type ThemeMode } from "../../hooks/useTheme.ts"

const OPTIONS: { value: ThemeMode; label: string; icon: ComponentType<SvgIconProps> }[] = [
    { value: "light", label: "Light", icon: LightModeOutlined },
    { value: "dark", label: "Dark", icon: DarkModeOutlined },
    { value: "system", label: "Match system", icon: SettingsBrightness },
]

/**
 * Appearance control.
 *
 * A menu rather than a two-way switch, because "follow the system" is a third state and a
 * toggle cannot express it — with a plain switch the user can never get back to it.
 */
export default function ThemeToggle({ size = "medium" }: { size?: "small" | "medium" }) {
    const { mode, resolvedMode, setMode } = useTheme()
    const [anchor, setAnchor] = useState<HTMLElement | null>(null)

    const active = OPTIONS.find((option) => option.value === mode) ?? OPTIONS[2]
    const Icon = resolvedMode === "dark" ? DarkModeOutlined : LightModeOutlined

    const open = (event: MouseEvent<HTMLElement>) => setAnchor(event.currentTarget)
    const close = () => setAnchor(null)

    return (
        <>
            <Tooltip title={`Appearance: ${active.label.toLowerCase()}`}>
                <IconButton
                    size={size}
                    onClick={open}
                    aria-label={`Change appearance, currently ${active.label.toLowerCase()}`}
                    aria-haspopup="menu"
                    aria-expanded={anchor !== null}
                    sx={{ color: "text.secondary" }}
                >
                    <Icon fontSize={size === "small" ? "small" : "medium"} />
                </IconButton>
            </Tooltip>

            <Menu
                anchorEl={anchor}
                open={anchor !== null}
                onClose={close}
                anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
                transformOrigin={{ vertical: "top", horizontal: "right" }}
            >
                {OPTIONS.map((option) => {
                    const OptionIcon = option.icon
                    const selected = option.value === mode

                    return (
                        <MenuItem
                            key={option.value}
                            selected={selected}
                            onClick={() => {
                                setMode(option.value)
                                close()
                            }}
                        >
                            <ListItemIcon>
                                <OptionIcon fontSize="small" />
                            </ListItemIcon>

                            <ListItemText primary={option.label} />

                            {/* The check is redundant with `selected`, but selection styling
                                alone is a colour-only signal. */}
                            {selected && (
                                <Check fontSize="small" sx={{ ml: 1.5, color: "primary.main" }} />
                            )}
                        </MenuItem>
                    )
                })}
            </Menu>
        </>
    )
}
