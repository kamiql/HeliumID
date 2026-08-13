import SvgIcon, { type SvgIconProps } from "@mui/material/SvgIcon"

/**
 * Provider marks.
 *
 * Each is a single inline `SvgIcon` on a 24-unit grid so it inherits `fontSize` and lines up
 * with the Material icons used everywhere else. Google keeps its brand colours because a
 * monochrome Google "G" is not a permitted use of the mark; GitHub and Discord follow the
 * surrounding text colour, which is what keeps them legible in both themes.
 */

export function GoogleIcon(props: SvgIconProps) {
    return (
        <SvgIcon viewBox="0 0 48 48" {...props}>
            <path
                fill="#FFC107"
                d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"
            />
            <path
                fill="#FF3D00"
                d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"
            />
            <path
                fill="#4CAF50"
                d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"
            />
            <path
                fill="#1976D2"
                d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 01-4.087 5.571l6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"
            />
        </SvgIcon>
    )
}

export function DiscordIcon(props: SvgIconProps) {
    return (
        <SvgIcon viewBox="0 0 24 24" {...props}>
            <path
                fill="currentColor"
                d="M20.317 4.369A19.79 19.79 0 0015.446 3c-.21.375-.454.88-.622 1.28a18.27 18.27 0 00-5.487 0A12.6 12.6 0 008.71 3a19.74 19.74 0 00-4.885 1.372C.73 8.99-.11 13.494.31 17.933a19.9 19.9 0 006.05 3.058c.489-.669.924-1.38 1.3-2.128a12.9 12.9 0 01-2.047-.985c.172-.126.34-.257.501-.392a14.2 14.2 0 0012.086 0c.163.14.331.271.5.392-.652.385-1.34.716-2.05.986.376.747.81 1.458 1.3 2.127a19.87 19.87 0 006.053-3.057c.5-5.148-.838-9.61-3.686-13.565zM8.02 15.278c-1.182 0-2.157-1.086-2.157-2.42 0-1.332.955-2.42 2.157-2.42 1.21 0 2.176 1.096 2.156 2.42 0 1.334-.955 2.42-2.156 2.42zm7.975 0c-1.183 0-2.157-1.086-2.157-2.42 0-1.332.955-2.42 2.157-2.42 1.21 0 2.176 1.096 2.156 2.42 0 1.334-.946 2.42-2.156 2.42z"
            />
        </SvgIcon>
    )
}

export function GitHubIcon(props: SvgIconProps) {
    return (
        <SvgIcon viewBox="0 0 24 24" {...props}>
            <path
                fill="currentColor"
                d="M12 .5C5.73.5.66 5.57.66 11.84c0 5.01 3.25 9.26 7.76 10.76.57.1.78-.25.78-.55l-.02-1.94c-3.16.69-3.83-1.52-3.83-1.52-.52-1.31-1.26-1.66-1.26-1.66-1.03-.71.08-.69.08-.69 1.14.08 1.74 1.17 1.74 1.17 1.01 1.74 2.66 1.24 3.31.95.1-.73.4-1.24.72-1.52-2.52-.29-5.17-1.26-5.17-5.61 0-1.24.44-2.25 1.17-3.05-.12-.29-.51-1.45.11-3.02 0 0 .95-.31 3.12 1.16.9-.25 1.87-.38 2.83-.38.96 0 1.93.13 2.83.38 2.16-1.47 3.11-1.16 3.11-1.16.62 1.57.23 2.73.11 3.02.73.8 1.17 1.81 1.17 3.05 0 4.36-2.66 5.32-5.19 5.6.41.35.77 1.05.77 2.12l-.01 3.14c0 .3.2.66.79.55 4.5-1.5 7.75-5.75 7.75-10.76C23.34 5.57 18.27.5 12 .5z"
            />
        </SvgIcon>
    )
}

/*
 * The provider id → icon map and the display-name helper live in `src/lib/providers.ts`:
 * this file exports components only, which is what keeps fast refresh working for every
 * module that imports an icon from here.
 */
