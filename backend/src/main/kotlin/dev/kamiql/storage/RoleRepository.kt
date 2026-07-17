package dev.kamiql.storage

import dev.kamiql.database.MongoRepository
import dev.kamiql.domain.security.Role
import java.util.UUID

object RoleRepository : MongoRepository<UUID, Role>("roles", Role.serializer())