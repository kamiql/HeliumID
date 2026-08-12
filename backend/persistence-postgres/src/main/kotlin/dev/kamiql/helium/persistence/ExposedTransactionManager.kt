package dev.kamiql.helium.persistence

import dev.kamiql.helium.flow.port.TransactionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.transactions.inTopLevelSuspendTransaction
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction

/**
 * Implements the flow engine's transaction port on Exposed.
 *
 * Nested calls **join** the outer transaction rather than opening a new one, which is what
 * lets a repository be written once and used both standalone (from a requirement, which runs
 * outside the flow transaction) and inside a flow transaction.
 *
 * JDBC is blocking, so the work runs on [Dispatchers.IO]. The pool bounds real concurrency;
 * the dispatcher only stops a blocked query from occupying an event-loop thread.
 */
class ExposedTransactionManager(private val database: Database) : TransactionManager {

    override suspend fun <T> transaction(block: suspend () -> T): T =
        withContext(Dispatchers.IO) {
            suspendTransaction(db = database) { block() }
        }

    /**
     * `outerTransaction = null` is what forces a genuinely separate transaction: without it
     * Exposed would nest, and the inner work would be discarded along with the outer rollback —
     * exactly the failure this method exists to avoid.
     */
    override suspend fun <T> requiresNew(block: suspend () -> T): T =
        withContext(Dispatchers.IO) {
            inTopLevelSuspendTransaction(db = database, outerTransaction = null) { block() }
        }
}

/**
 * Runs a repository operation, joining the caller's transaction when there is one.
 *
 * Every repository method funnels through here. Repositories therefore never decide when to
 * commit — that authority belongs to the flow engine alone.
 */
internal suspend fun <T> dbQuery(database: Database, block: suspend () -> T): T =
    withContext(Dispatchers.IO) {
        suspendTransaction(db = database) { block() }
    }
