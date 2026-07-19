import {createContext, useContext} from "react";

export type AccountBoxContextValue = {
    disabled: boolean
}

export const AccountBoxContext = createContext<AccountBoxContextValue>({
    disabled: false,
})

export const useAccountBox = () => useContext(AccountBoxContext)