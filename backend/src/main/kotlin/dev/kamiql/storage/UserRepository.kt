package dev.kamiql.storage

import dev.kamiql.database.MongoRepository
import dev.kamiql.domain.user.User
import java.util.*

object UserRepository : MongoRepository<UUID, User>(
    "users",
    User.serializer()
)