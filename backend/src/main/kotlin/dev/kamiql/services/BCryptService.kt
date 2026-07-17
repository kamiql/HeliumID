package dev.kamiql.services

import at.favre.lib.crypto.bcrypt.BCrypt

object BCryptService {
    fun hash(password: String): String {
        return BCrypt.withDefaults()
            .hashToString(12, password.toCharArray())
    }

    fun verify(password: String, hash: String): Boolean {
        return BCrypt.verifyer()
            .verify(password.toCharArray(), hash)
            .verified
    }
}