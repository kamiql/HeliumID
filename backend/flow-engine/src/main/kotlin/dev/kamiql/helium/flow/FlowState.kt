package dev.kamiql.helium.flow

/**
 * Typed key for a value passed between steps of one flow execution.
 *
 * Keys are declared as `val`s next to the steps that use them, so "who writes this and who
 * reads it" is answerable by find-usages. A stringly-typed map would make that invisible.
 *
 * @param sensitive when true the value is excluded from any diagnostic dump of the state.
 *        Concept §8.4: "Do not pass the decrypted secret through logs, generic flow metadata,
 *        or serialized state."
 */
class FlowStateKey<T : Any>(val name: String, val sensitive: Boolean = false) {
    override fun toString(): String = name
}

/** Read-only view handed to effects and result builders. */
interface FlowState {
    operator fun <T : Any> get(key: FlowStateKey<T>): T?

    /**
     * @throws IllegalStateException when the key is absent. Absence is a programming error —
     *         a step that should have run did not — so it is loud rather than silent.
     */
    fun <T : Any> require(key: FlowStateKey<T>): T =
        get(key) ?: error("flow state '${key.name}' was never set")
}

/** Mutable view handed to steps. */
class MutableFlowState : FlowState {

    private val values = LinkedHashMap<FlowStateKey<*>, Any>()

    @Suppress("UNCHECKED_CAST")
    override fun <T : Any> get(key: FlowStateKey<T>): T? = values[key] as T?

    operator fun <T : Any> set(key: FlowStateKey<T>, value: T) {
        values[key] = value
    }

    /** Removes a value once it is no longer needed — used to drop plaintext after hashing. */
    fun clear(key: FlowStateKey<*>) {
        values.remove(key)
    }

    /**
     * Non-sensitive keys only, for audit metadata and debugging.
     *
     * Values are rendered with `toString()`, which is why every secret-bearing type in this
     * codebase has a redacting `toString()` as a second line of defence.
     */
    fun diagnosticSnapshot(): Map<String, String> =
        values.entries
            .filterNot { it.key.sensitive }
            .associate { (key, value) -> key.name to value.toString() }
}
