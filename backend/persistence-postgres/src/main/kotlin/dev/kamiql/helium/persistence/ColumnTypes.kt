package dev.kamiql.helium.persistence

import org.jetbrains.exposed.v1.core.BasicUuidColumnType
import org.jetbrains.exposed.v1.core.Column
import org.jetbrains.exposed.v1.core.Table
import java.nio.ByteBuffer
import java.util.UUID

/**
 * A `uuid` column typed as [java.util.UUID].
 *
 * Exposed 1.0's built-in `Table.uuid()` produces a `kotlin.uuid.Uuid` column. The domain model
 * uses `java.util.UUID`, so rather than sprinkling opt-ins for the experimental Kotlin UUID
 * API through every repository — or worse, letting a persistence-library type dictate a domain
 * type — the conversion is confined to this one column type.
 */
class JavaUuidColumnType : BasicUuidColumnType<UUID>() {

    override fun valueFromDB(value: Any): UUID = when (value) {
        is UUID -> value
        is String -> UUID.fromString(value)
        is ByteArray -> ByteBuffer.wrap(value).let { UUID(it.long, it.long) }
        else -> error("unexpected uuid value of type ${value::class.qualifiedName}")
    }

    override fun notNullValueToDB(value: UUID): Any = value
}

/** Registers a `uuid` column carrying [java.util.UUID]. */
fun Table.javaUuid(name: String): Column<UUID> = registerColumn(name, JavaUuidColumnType())
