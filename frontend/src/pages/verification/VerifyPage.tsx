import { useSearchParams } from "react-router";
import {
    Button,
    Typography,
    Paper,
    Container,
    Box,
    CircularProgress,
    Alert,
} from "@mui/material";
import { useState } from "react";
import axios from "axios";
import {verificationApi} from "../../api/user.ts";

export default function VerifyPage() {
    const [searchParams] = useSearchParams();

    const id = searchParams.get("id");
    const type = searchParams.get("type");
    const secret = searchParams.get("secret");

    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleVerify = async () => {
        setError(null);
        setLoading(true);

        try {
            await verificationApi.verify(id!, type!, secret!)

            setSuccess(true);
        } catch (err: unknown) {
            let errorMessage = "Verification failed. Please try again.";

            if (axios.isAxiosError(err)) {
                if (err.response) {
                    const status = err.response.status;
                    const data = err.response.data;

                    if (data?.message) {
                        errorMessage = data.message;
                    } else {
                        switch (status) {
                            case 400:
                                errorMessage = "Invalid verification request.";
                                break;
                            case 404:
                                errorMessage = "Verification link not found or expired.";
                                break;
                            case 500:
                                errorMessage = "Server error. Please try again later.";
                                break;
                            default:
                                errorMessage = `Error ${status}: ${err.message}`;
                        }
                    }
                } else if (err.request) {
                    errorMessage = "Network error.";
                } else {
                    errorMessage = err.message || errorMessage;
                }
            } else {
                errorMessage = err instanceof Error ? err.message : errorMessage;
            }

            setError(errorMessage);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Container maxWidth="sm" sx={{ mt: 8 }}>
            <Paper elevation={3} sx={{ p: 4, textAlign: "center" }}>
                {success ? (
                    <>
                        <Typography
                            variant="h5"
                            gutterBottom
                            color="success.main"
                        >
                            Verification successful!
                        </Typography>

                        <Typography variant="body1">
                            Your email has been verified.
                        </Typography>

                        <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{ mt: 1 }}
                        >
                            You can close this window now.
                        </Typography>
                    </>
                ) : (
                    <>
                        <Typography variant="h5" gutterBottom>
                            Verify your email
                        </Typography>

                        {error && (
                            <Alert severity="error" sx={{ mb: 2 }}>
                                {error}
                            </Alert>
                        )}

                        <Box sx={{ mt: 2 }}>
                            <Button
                                variant="contained"
                                onClick={handleVerify}
                                disabled={loading || !secret}
                                startIcon={
                                    loading ? (
                                        <CircularProgress size={20} />
                                    ) : null
                                }
                            >
                                {loading ? "Verifying..." : "Confirm"}
                            </Button>
                        </Box>
                    </>
                )}
            </Paper>
        </Container>
    );
}