package dev.kamiql.helium.demo.domain

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * The application's own authorization model.
 *
 * This is axis one of three, and the one HeliumID deliberately knows nothing about. Who may edit
 * *this document* is a fact about this product, not about the identity provider: HeliumID has no
 * per-application permissions and no tenancy, and pushing "editor of document 7" into it would
 * mean inventing both.
 *
 * What HeliumID supplies is the stable identity these grants hang from — the `sub` claim. Not the
 * username or the email, both of which the user can change under you.
 */
enum class DocumentRole(val label: String) {
    /** May read, write, share and delete. Assigned to whoever created the document. */
    OWNER("Owner"),

    /** May read and write, but not share or delete. */
    EDITOR("Editor"),

    /** May read. Nothing else. */
    VIEWER("Viewer"),
    ;

    val canRead: Boolean get() = true
    val canWrite: Boolean get() = this == OWNER || this == EDITOR
    val canShare: Boolean get() = this == OWNER
    val canDelete: Boolean get() = this == OWNER
}

data class Document(
    val id: Long,
    val title: String,
    val body: String,
    /** HeliumID `sub` to role. The creator is always present as [DocumentRole.OWNER]. */
    val grants: Map<String, DocumentRole>,
    val createdAt: Instant,
    val updatedAt: Instant,
) {
    fun roleOf(subject: String): DocumentRole? = grants[subject]
}

/** What a caller is allowed to do with a document they can see. */
data class DocumentView(val document: Document, val role: DocumentRole)

/** Why an operation was refused. Distinct cases, because they map to different responses. */
sealed interface WorkspaceError {
    /** No such document, *or* one the caller may not see. Deliberately the same answer. */
    data object NotFound : WorkspaceError

    /** Visible, but not with the role required for this operation. */
    data class Forbidden(val required: String) : WorkspaceError
}

sealed interface WorkspaceResult<out T> {
    data class Ok<T>(val value: T) : WorkspaceResult<T>
    data class Failed(val error: WorkspaceError) : WorkspaceResult<Nothing>
}

/**
 * In-memory document store.
 *
 * A database here would teach nothing about HeliumID and would make the example a two-service
 * setup. The authorization decisions are the part worth reading.
 */
class Workspace {

    private val documents = ConcurrentHashMap<Long, Document>()
    private val ids = AtomicLong(0)

    /**
     * Documents the caller has any grant on.
     *
     * Filtering at the source rather than fetching everything and hiding rows in the view: a
     * template that forgets a check is a leak, a query that never returns the row cannot be.
     */
    fun visibleTo(subject: String): List<DocumentView> = documents.values
        .mapNotNull { document -> document.roleOf(subject)?.let { DocumentView(document, it) } }
        .sortedByDescending { it.document.updatedAt }

    fun create(subject: String, title: String, body: String, now: Instant): Document {
        val document = Document(
            id = ids.incrementAndGet(),
            title = title,
            body = body,
            grants = mapOf(subject to DocumentRole.OWNER),
            createdAt = now,
            updatedAt = now,
        )
        documents[document.id] = document
        return document
    }

    /**
     * One document, if the caller has any grant on it.
     *
     * A caller with no grant gets [WorkspaceError.NotFound] rather than a forbidden — the same
     * answer they get for an id that never existed. Telling them apart would confirm which
     * document ids are real, which is an enumeration oracle for a resource they cannot read.
     */
    fun read(subject: String, id: Long): WorkspaceResult<DocumentView> {
        val document = documents[id] ?: return WorkspaceResult.Failed(WorkspaceError.NotFound)
        val role = document.roleOf(subject) ?: return WorkspaceResult.Failed(WorkspaceError.NotFound)
        return WorkspaceResult.Ok(DocumentView(document, role))
    }

    fun update(subject: String, id: Long, title: String, body: String, now: Instant): WorkspaceResult<Document> =
        mutate(subject, id, required = DocumentRole::canWrite, requirement = "editor") { document ->
            document.copy(title = title, body = body, updatedAt = now)
        }

    /** Shares with another HeliumID user. Owner only: sharing is how access spreads. */
    fun share(subject: String, id: Long, withSubject: String, role: DocumentRole, now: Instant):
        WorkspaceResult<Document> =
        mutate(subject, id, required = DocumentRole::canShare, requirement = "owner") { document ->
            // An owner cannot be demoted by a share, or the last owner could be shared away and
            // the document left with nobody able to delete it.
            if (document.roleOf(withSubject) == DocumentRole.OWNER) document
            else document.copy(grants = document.grants + (withSubject to role), updatedAt = now)
        }

    fun delete(subject: String, id: Long): WorkspaceResult<Unit> {
        val document = documents[id] ?: return WorkspaceResult.Failed(WorkspaceError.NotFound)
        val role = document.roleOf(subject) ?: return WorkspaceResult.Failed(WorkspaceError.NotFound)
        if (!role.canDelete) return WorkspaceResult.Failed(WorkspaceError.Forbidden("owner"))
        documents.remove(id)
        return WorkspaceResult.Ok(Unit)
    }

    private fun mutate(
        subject: String,
        id: Long,
        required: (DocumentRole) -> Boolean,
        requirement: String,
        change: (Document) -> Document,
    ): WorkspaceResult<Document> {
        val document = documents[id] ?: return WorkspaceResult.Failed(WorkspaceError.NotFound)
        val role = document.roleOf(subject) ?: return WorkspaceResult.Failed(WorkspaceError.NotFound)
        if (!required(role)) return WorkspaceResult.Failed(WorkspaceError.Forbidden(requirement))

        val updated = change(document)
        documents[id] = updated
        return WorkspaceResult.Ok(updated)
    }
}
