package dev.kamiql.helium.client

import io.ktor.client.call.body
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json

/**
 * Shared JSON codec for the SDK.
 *
 * `ignoreUnknownKeys` is not laziness: the identity server is versioned independently of this
 * SDK, and a new response field must never break an older client. `explicitNulls = false` keeps
 * "leave unchanged" patch semantics working — a `null` property is omitted rather than sent as
 * an explicit `null` that would clear the value.
 */
internal val HeliumJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = true
    isLenient = false
}

/**
 * Turns a non-2xx response into a typed [HeliumApiException], and does nothing otherwise.
 *
 * Both error shapes the server uses are handled: RFC 9457 problem+json everywhere, and RFC 6749
 * `{"error": ...}` at the OAuth protocol endpoints. The body is read as text and parsed here
 * rather than through content negotiation, because an error response from a proxy or a load
 * balancer will not be JSON at all and must still produce a usable exception.
 */
internal suspend fun HttpResponse.heliumEnsureSuccess() {
    if (status.isSuccess()) return

    val retryAfterHeader = headers[HttpHeaders.RetryAfter]?.toLongOrNull()
    val text = runCatching { bodyAsText() }.getOrElse { "" }

    if (text.isNotBlank()) {
        runCatching { HeliumJson.decodeFromString(ProblemDetails.serializer(), text) }
            .getOrNull()
            ?.takeIf { it.code.isNotBlank() }
            ?.let { throw HeliumApiException(it.toHeliumError(status.value, retryAfterHeader)) }

        runCatching { HeliumJson.decodeFromString(OAuthErrorResponse.serializer(), text) }
            .getOrNull()
            ?.takeIf { it.error.isNotBlank() }
            ?.let { throw HeliumApiException(it.toHeliumError(status.value, retryAfterHeader)) }
    }

    // Not a HeliumID error document. Report the status honestly rather than guessing a code,
    // and never echo the body: it came from something in the middle and may contain anything.
    throw HeliumApiException(
        HeliumError.Unexpected(
            status = status.value,
            code = "unexpected_response",
            detail = "The identity server returned an unrecognised ${status.value} response.",
        ),
    )
}

/** Checks the status, then decodes the body. The single funnel every typed call goes through. */
internal suspend inline fun <reified T> HttpResponse.heliumBody(): T {
    heliumEnsureSuccess()
    return body()
}
