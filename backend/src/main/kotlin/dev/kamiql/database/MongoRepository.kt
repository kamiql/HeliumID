package dev.kamiql.database

import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoDatabase
import com.mongodb.client.model.Filters
import com.mongodb.client.model.ReplaceOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import org.bson.Document
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

abstract class MongoRepository<K, V>(
    collection: String,
    private val serializer: KSerializer<V>
) : KoinComponent {
    protected val database: MongoDatabase by inject()
    protected val json: Json by inject()

    private val collection: MongoCollection<Document> = database.getCollection(collection)

    suspend operator fun set(id: K, value: V) {
        withContext(Dispatchers.IO) {
            val document = Document.parse(
                json.encodeToString(serializer, value)
            )

            document["_id"] = id

            collection.replaceOne(
                Filters.eq("_id", id),
                document,
                ReplaceOptions().upsert(true)
            )
        }
    }

    suspend operator fun get(id: K): V? {
        return withContext(Dispatchers.IO) {
            val document = collection
                .find(Filters.eq("_id", id))
                .firstOrNull()
                ?: return@withContext null

            json.decodeFromString(
                serializer,
                document.toJson()
            )
        }
    }

    suspend fun delete(id: K) {
        withContext(Dispatchers.IO) {
            collection.deleteOne(
                Filters.eq("_id", id)
            )
        }
    }

    suspend fun findAll(): Map<K, V> {
        return withContext(Dispatchers.IO) {
            collection.find().associate { document ->
                val key = document["_id"] as K
                val value = json.decodeFromString(
                    serializer,
                    document.toJson()
                )

                key to value
            }
        }
    }

    suspend fun existsBy(field: String, value: Any): Boolean {
        return withContext(Dispatchers.IO) {
            collection.find(
                Filters.eq(field, value)
            ).firstOrNull() != null
        }
    }

    suspend fun findBy(field: String, value: Any): V? {
        return withContext(Dispatchers.IO) {
            val document = collection.find(
                Filters.eq(field, value)
            ).firstOrNull() ?: return@withContext null

            json.decodeFromString(
                serializer,
                document.toJson()
            )
        }
    }
}