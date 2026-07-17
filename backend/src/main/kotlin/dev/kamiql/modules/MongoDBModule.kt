package dev.kamiql.modules

import com.mongodb.ConnectionString
import com.mongodb.MongoClientSettings
import com.mongodb.client.MongoClient
import com.mongodb.client.MongoClients
import io.github.cdimascio.dotenv.Dotenv
import org.bson.UuidRepresentation
import org.koin.dsl.module

val MongoDBModule = module {
    single {
        val dotenv: Dotenv = get()

        MongoClients.create(
            MongoClientSettings.builder()
                .uuidRepresentation(UuidRepresentation.STANDARD)
                .applyConnectionString(ConnectionString(dotenv["MONGODB_URI"]))
                .build()
        )
    }

    single {
        val dotenv: Dotenv = get()

        get<MongoClient>().getDatabase(
            dotenv["MONGODB_DATABASE"]
        )
    }
}