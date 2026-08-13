package dev.kamiql.helium.app

import dev.kamiql.helium.api.MetricsEndpoint
import dev.kamiql.helium.audit.MetricNames
import dev.kamiql.helium.flow.port.MetricsPort
import io.micrometer.core.instrument.Tag
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

/**
 * The metrics registry, and both ends of it.
 *
 * One object implements [MetricsPort] — what the flow engine writes to — and [MetricsEndpoint] —
 * what `/metrics` reads from. They are separate interfaces because they point in opposite
 * directions and live in different modules; they are one class because there is exactly one
 * registry and pretending otherwise would let the two drift onto different backends.
 *
 * ### Label discipline is enforced, not documented
 *
 * `docs/operations.md` §6 warns that an unbounded label will take down the metrics backend and
 * put identifiers somewhere with a very different access policy from the database. A warning in
 * a document does not stop a call site from passing an email address, so [MetricNames.ALLOWED_LABELS]
 * is applied here: anything outside the allowlist is dropped and logged once per key. Dropping
 * rather than throwing is deliberate — a mislabelled counter must not be able to fail a login.
 */
class HeliumMetrics : MetricsPort, MetricsEndpoint {

    private val log = LoggerFactory.getLogger(HeliumMetrics::class.java)

    val registry: PrometheusMeterRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    /** Keys already reported, so a hot path cannot turn a naming mistake into a log flood. */
    private val reportedRejections = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    override fun counter(name: String, tags: Map<String, String>, amount: Double) {
        registry.counter(name, tags.toMicrometerTags(name)).increment(amount)
    }

    override fun timer(name: String, durationNanos: Long, tags: Map<String, String>) {
        registry.timer(name.asTimerName(), tags.toMicrometerTags(name))
            .record(durationNanos, TimeUnit.NANOSECONDS)
    }

    override fun scrape(): String = registry.scrape()

    /**
     * Strips a `_nanos` suffix from timer names.
     *
     * The port speaks nanoseconds because that is what `System.nanoTime()` yields, but Micrometer
     * owns the unit of a `Timer` and Prometheus renders it as `_seconds`. Leaving the suffix on
     * would publish `helium_flow_duration_nanos_seconds`, which is both ugly and a lie.
     */
    private fun String.asTimerName(): String = removeSuffix("_nanos")

    private fun Map<String, String>.toMicrometerTags(metric: String): List<Tag> =
        mapNotNull { (key, value) ->
            if (key in MetricNames.ALLOWED_LABELS) {
                Tag.of(key, value)
            } else {
                if (reportedRejections.add("$metric/$key")) {
                    log.warn(
                        "dropping metric label '{}' on '{}': not in MetricNames.ALLOWED_LABELS",
                        key, metric,
                    )
                }
                null
            }
        }
}
