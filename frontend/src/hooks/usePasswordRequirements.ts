import {useEffect, useState} from "react";
import {api} from "../api/axios.ts";

export type PasswordRequirement = {
    regex: string;
    description: string;
};

export type PasswordRequirements = Record<
    string,
    PasswordRequirement
>;

export function usePasswordRequirements(): PasswordRequirements | null {
    const [requirements, setRequirements] = useState<PasswordRequirements | null>(null);

    useEffect(() => {
        api.get<PasswordRequirements>("/data/passwordRequirements")
            .then(response => setRequirements(response.data));
    }, []);

    return requirements;
}