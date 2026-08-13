package dev.kamiql.helium.demo

import dev.kamiql.helium.demo.domain.DocumentRole
import dev.kamiql.helium.demo.domain.Workspace
import dev.kamiql.helium.demo.domain.WorkspaceError
import dev.kamiql.helium.demo.domain.WorkspaceResult
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The application's own authorization rules — axis one.
 *
 * These say nothing about OAuth, and that is the point: what a user may do *inside this product*
 * is this product's decision. HeliumID supplies only the `sub` these grants hang from.
 */
class WorkspaceTest {

    private val now: Instant = Instant.parse("2026-08-13T10:00:00Z")
    private val alice = "user-alice"
    private val bob = "user-bob"
    private val stranger = "user-stranger"

    private fun workspaceWithSharedDocument(role: DocumentRole): Pair<Workspace, Long> {
        val workspace = Workspace()
        val document = workspace.create(alice, "Plan", "body", now)
        workspace.share(alice, document.id, bob, role, now)
        return workspace to document.id
    }

    @Test
    fun `the creator owns the document`() {
        val workspace = Workspace()
        val document = workspace.create(alice, "Plan", "body", now)

        assertEquals(DocumentRole.OWNER, document.roleOf(alice))
        assertTrue(document.roleOf(alice)!!.canDelete)
    }

    @Test
    fun `a viewer may read but not write`() {
        val (workspace, id) = workspaceWithSharedDocument(DocumentRole.VIEWER)

        assertIs<WorkspaceResult.Ok<*>>(workspace.read(bob, id))

        val write = assertIs<WorkspaceResult.Failed>(workspace.update(bob, id, "Hijacked", "x", now))
        assertEquals(WorkspaceError.Forbidden("editor"), write.error)
        // And the document is untouched, not merely the response refused.
        val stored = assertIs<WorkspaceResult.Ok<*>>(workspace.read(alice, id))
        assertEquals("Plan", (stored.value as dev.kamiql.helium.demo.domain.DocumentView).document.title)
    }

    @Test
    fun `an editor may write but not share or delete`() {
        val (workspace, id) = workspaceWithSharedDocument(DocumentRole.EDITOR)

        assertIs<WorkspaceResult.Ok<*>>(workspace.update(bob, id, "Revised", "body", now))

        assertEquals(
            WorkspaceError.Forbidden("owner"),
            assertIs<WorkspaceResult.Failed>(workspace.share(bob, id, stranger, DocumentRole.VIEWER, now)).error,
        )
        assertEquals(
            WorkspaceError.Forbidden("owner"),
            assertIs<WorkspaceResult.Failed>(workspace.delete(bob, id)).error,
        )
    }

    /**
     * A document nobody shared answers exactly like a document that does not exist.
     *
     * Distinguishing the two would confirm which ids are real, which is an enumeration oracle for
     * a resource the caller cannot read either way.
     */
    @Test
    fun `a stranger cannot tell an unshared document from a missing one`() {
        val (workspace, id) = workspaceWithSharedDocument(DocumentRole.VIEWER)

        val unshared = assertIs<WorkspaceResult.Failed>(workspace.read(stranger, id))
        val missing = assertIs<WorkspaceResult.Failed>(workspace.read(stranger, 9_999))

        assertEquals(WorkspaceError.NotFound, unshared.error)
        assertEquals(missing.error, unshared.error)
    }

    @Test
    fun `listing shows only documents the caller has a grant on`() {
        val workspace = Workspace()
        val mine = workspace.create(alice, "Mine", "", now)
        val shared = workspace.create(bob, "Shared", "", now)
        workspace.create(bob, "Not mine", "", now)
        workspace.share(bob, shared.id, alice, DocumentRole.VIEWER, now)

        val visible = workspace.visibleTo(alice).map { it.document.id }.toSet()

        assertEquals(setOf(mine.id, shared.id), visible)
    }

    /** Otherwise the last owner could be shared away, leaving a document nobody can delete. */
    @Test
    fun `sharing cannot demote an owner`() {
        val workspace = Workspace()
        val document = workspace.create(alice, "Plan", "", now)

        workspace.share(alice, document.id, alice, DocumentRole.VIEWER, now)

        val stored = assertIs<WorkspaceResult.Ok<*>>(workspace.read(alice, document.id))
        assertEquals(
            DocumentRole.OWNER,
            (stored.value as dev.kamiql.helium.demo.domain.DocumentView).role,
        )
    }
}
