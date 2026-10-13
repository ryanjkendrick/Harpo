using Harpo.Data;
using Harpo.Security;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Services;

public sealed record GroupSummary(Group Group, GroupRole? MyRole, int MemberCount, int EntryCount);

/// <summary>
/// The membership <see cref="GroupService.AddMemberAsync"/> stored. <see cref="Verified"/>
/// is false when the directory could not be asked, so the page can say the name
/// was taken as typed.
/// </summary>
public sealed record MemberAdded(string Username, string DisplayName, bool Verified);

/// <summary>A personal vault as a site admin sees it: whose it is and how full, never what is in it.</summary>
public sealed record PersonalVaultSummary(Group Group, string OwnerDisplayName, int EntryCount);

/// <summary>
/// Group and membership management. Authorization model:
///  - any authenticated user may create a group and becomes its admin;
///  - group members see the group and its passwords;
///  - group admins additionally manage members and the group itself;
///  - site admins (from the AD admin group) can do everything — except open a
///    personal vault. Each user has one; only its owner sees inside it, it has
///    no members or settings to manage, and the single thing an admin can do
///    with it is convert it into an ordinary group (<see cref="TakeOverPersonalVaultAsync"/>).
/// All checks live here, server-side — the UI only hides buttons.
/// </summary>
public class GroupService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly TimeProvider _time;
    private readonly AuditService _audit;
    private readonly SessionService _sessions;
    private readonly IDirectory _directory;

    public GroupService(IDbContextFactory<HarpoDbContext> dbFactory, TimeProvider time, AuditService audit,
        SessionService sessions, IDirectory directory)
    {
        _dbFactory = dbFactory;
        _time = time;
        _audit = audit;
        _sessions = sessions;
        _directory = directory;
    }

    // Every public method taking a UserContext first checks that the caller's
    // session is still live (SessionService.RequireLiveAsync) — an open page
    // keeps its user after a sign-out elsewhere. Always before taking the write
    // gate, so the check never waits behind it.

    public async Task<List<GroupSummary>> GetMyGroupsAsync(UserContext user, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var memberships = await db.GroupMembers
            .Where(m => !m.IsDeleted && m.Username == user.Username)
            .ToDictionaryAsync(m => m.GroupId, m => m.Role, ct);

        var groups = await VisibleGroups(db, user, memberships.Keys)
            .OrderBy(g => g.OwnerUsername == "" ? 1 : 0)
            .ThenBy(g => g.Name)
            .ToListAsync(ct);

        var ids = groups.Select(g => g.Id).ToList();
        var memberCounts = await db.GroupMembers
            .Where(m => !m.IsDeleted && ids.Contains(m.GroupId))
            .GroupBy(m => m.GroupId)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var entryCounts = await db.PasswordEntries
            .Where(e => !e.IsDeleted && ids.Contains(e.GroupId))
            .GroupBy(e => e.GroupId)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);

        return groups
            .Select(g => new GroupSummary(
                g,
                memberships.TryGetValue(g.Id, out var role) ? role : null,
                memberCounts.GetValueOrDefault(g.Id),
                entryCounts.GetValueOrDefault(g.Id)))
            .ToList();
    }

    /// <summary>
    /// The live groups a user may see in the vault: explicit memberships, every
    /// shared group for a site admin, and their own personal vault. A personal
    /// vault is listed for its owner alone — a site admin's see-everything
    /// right stops at it, and so would a membership row that somehow got
    /// attached to it. Shared with <see cref="VaultService.SearchEntriesAsync"/>
    /// so that search can never reach a vault the listing would not show.
    /// </summary>
    internal static IQueryable<Group> VisibleGroups(
        HarpoDbContext db, UserContext user, IEnumerable<Guid> memberGroupIds)
    {
        var groupsQuery = db.Groups
            .Where(g => !g.IsDeleted && (g.OwnerUsername == "" || g.OwnerUsername == user.Username));
        if (!user.IsSiteAdmin)
        {
            var groupIds = memberGroupIds.ToList();
            groupsQuery = groupsQuery.Where(g => groupIds.Contains(g.Id));
        }
        return groupsQuery;
    }

    public async Task<Group> CreateGroupAsync(UserContext user, string name, string description, CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Group name is required.", "name");
        }

        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var now = _time.GetUtcNow().UtcDateTime;
        var group = new Group
        {
            Id = Guid.NewGuid(),
            Name = name,
            Description = description.Trim(),
            CreatedBy = user.Username,
            CreatedAtUtc = now,
        };
        db.Groups.Add(group);
        db.GroupMembers.Add(new GroupMember
        {
            Id = DeterministicGuid.For(group.Id.ToString("N"), user.Username),
            GroupId = group.Id,
            Username = user.Username,
            DisplayName = user.DisplayName,
            Role = GroupRole.Admin,
            AddedBy = user.Username,
            CreatedAtUtc = now,
            Verified = true, // the creator's identity came from the directory at sign-in
        });
        await db.SaveChangesAsync(ct);
        return group;
    }

    public async Task<(Group Group, GroupRole? MyRole)> GetGroupAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
        RequireNotSomeoneElsesPersonalVault(group, user);
        var role = await GetRoleAsync(db, groupId, user.Username, ct);
        if (role is null && !user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("You are not a member of this group.");
        }
        return (group, role);
    }

    public async Task UpdateGroupAsync(UserContext user, Guid groupId, string name, string description, CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Group name is required.", "name");
        }

        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await RequireGroupAdminAsync(db, user, groupId, ct);
        group.Name = name;
        group.Description = description.Trim();
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteGroupAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await RequireGroupAdminAsync(db, user, groupId, ct);
        group.IsDeleted = true;
        await db.SaveChangesAsync(ct);
        await _audit.RecordAsync(user, AuditActions.GroupDelete, group.Name, groupId: groupId);
    }

    public const int DeletedPageSize = 50;

    /// <summary>
    /// A page of tombstoned groups, newest first, plus the true total. Site admins only. Paged by the compound
    /// (UpdatedAtUtc, Id) key so tied timestamps are neither skipped nor repeated.
    /// </summary>
    public async Task<DeletedPage<Group>> GetDeletedGroupsAsync(
        UserContext user, DeletedCursor? after = null, int pageSize = DeletedPageSize, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site admins can see deleted groups.");
        }
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var deleted = db.Groups.Where(g => g.IsDeleted && g.OwnerUsername == "");
        var total = await deleted.CountAsync(ct);
        var page = after is null
            ? deleted
            : deleted.Where(g => g.UpdatedAtUtc < after.UpdatedAtUtc
                || (g.UpdatedAtUtc == after.UpdatedAtUtc && g.Id.CompareTo(after.Id) < 0));
        var items = await page
            .OrderByDescending(g => g.UpdatedAtUtc).ThenByDescending(g => g.Id)
            .Take(pageSize)
            .ToListAsync(ct);
        return new DeletedPage<Group>(items, total);
    }

    /// <summary>Restores a deleted group; its entries that were not individually deleted come back with it.</summary>
    public async Task RestoreGroupAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site admins can restore deleted groups.");
        }
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && g.IsDeleted && g.OwnerUsername == "", ct)
            ?? throw new VaultNotFoundException("Deleted group not found.");
        group.IsDeleted = false;
        await db.SaveChangesAsync(ct);
        await _audit.RecordAsync(user, AuditActions.GroupRestore, group.Name, groupId: groupId);
    }

    public async Task<List<GroupMember>> GetMembersAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await GetGroupAsync(user, groupId, ct); // access check
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.GroupMembers
            .Where(m => m.GroupId == groupId && !m.IsDeleted)
            .OrderBy(m => m.Username)
            .ToListAsync(ct);
    }

    /// <summary>Most suggestions <see cref="SearchAccountsAsync"/> returns.</summary>
    public const int AccountSuggestionLimit = 10;

    /// <summary>
    /// Directory accounts matching <paramref name="term"/>, as suggestions for
    /// the add-member field. Only someone who may add members to
    /// <paramref name="groupId"/> may search, so the directory is not an open
    /// phone book for every signed-in user. Unavailable when the directory
    /// cannot be asked (LDAP without a service account, or the server is down).
    /// </summary>
    public async Task<DirectorySearchResult> SearchAccountsAsync(UserContext user, Guid groupId, string term, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            await RequireGroupAdminAsync(db, user, groupId, ct);
        }
        term = term.Trim();
        if (term.Length == 0)
        {
            return new DirectorySearchResult(true, []);
        }
        return await _directory.SearchAccountsAsync(term, AccountSuggestionLimit, ct);
    }

    /// <summary>
    /// Adds <paramref name="username"/> to the group, after asking the directory
    /// who that is. A name the directory does not know, or knows as disabled,
    /// is refused — a typo would otherwise grant access to nobody today and to
    /// whoever is given that name tomorrow. The display name stored is the
    /// directory's, not what was typed.
    /// <para>
    /// When the directory cannot be asked, the membership is still made, from
    /// the name and display name as typed, and recorded as unverified (on the
    /// row, in the audit detail, and in the result). That is deliberate: in
    /// LDAP mode the asking needs <c>Auth:Ldap:ServiceUser</c>, which is
    /// optional, and deployments without one must still be able to add people.
    /// Whether verification is enforced is the operator's choice, made by
    /// configuring the service account.
    /// </para>
    /// </summary>
    public async Task<MemberAdded> AddMemberAsync(UserContext user, Guid groupId, string username, string displayName, GroupRole role, CancellationToken ct = default)
    {
        username = username.Trim().ToLowerInvariant();
        if (username.Length == 0)
        {
            throw new VaultValidationException("Username is required.");
        }

        await _sessions.RequireLiveAsync(user, ct);
        // Rights first, so the directory answers only those allowed to add
        // members — the refusals below say whether an account exists. The
        // lookup happens outside the write gate (it is a network round trip);
        // the rights are checked again inside it.
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            await RequireGroupAdminAsync(db, user, groupId, ct);
        }
        var lookup = await _directory.LookupAccountAsync(username, ct);
        bool verified;
        switch (lookup.Status)
        {
            case DirectoryLookupStatus.Found:
                var account = lookup.Account!;
                if (account.Disabled)
                {
                    throw new VaultValidationException($"'{account.Username}' is disabled in the directory.");
                }
                username = account.Username;
                displayName = account.DisplayName;
                verified = true;
                break;
            case DirectoryLookupStatus.NotFound:
                throw new VaultValidationException($"No account named '{username}' in the directory.");
            case DirectoryLookupStatus.Ambiguous:
                throw new VaultValidationException(
                    $"More than one account in the directory is named '{username}'; ask an administrator to narrow Auth:Ldap:SearchBase.");
            default:
                verified = false;
                break;
        }

        Group group;
        string storedDisplayName;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            // "Is this user already a member?" and the insert are one atomic step.
            // Checked separately, two admins adding the same person at the same
            // moment would both find nobody there, and the second insert would
            // fail on the membership's key — an error page instead of the plain
            // "already a member" the first check exists to give.
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            group = await RequireGroupAdminAsync(db, user, groupId, ct);

            var id = DeterministicGuid.For(groupId.ToString("N"), username);
            var existing = await db.GroupMembers.SingleOrDefaultAsync(m => m.Id == id, ct);
            if (existing is not null && !existing.IsDeleted)
            {
                throw new VaultValidationException($"'{username}' is already a member of this group.");
            }

            var now = _time.GetUtcNow().UtcDateTime;
            if (existing is not null)
            {
                // Revive the tombstoned membership.
                existing.IsDeleted = false;
                existing.Role = role;
                existing.DisplayName = string.IsNullOrWhiteSpace(displayName) ? existing.DisplayName : displayName.Trim();
                existing.AddedBy = user.Username;
                existing.CreatedAtUtc = now;
                existing.Verified = verified;
                storedDisplayName = existing.DisplayName;
            }
            else
            {
                storedDisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim();
                db.GroupMembers.Add(new GroupMember
                {
                    Id = id,
                    GroupId = groupId,
                    Username = username,
                    DisplayName = storedDisplayName,
                    Role = role,
                    AddedBy = user.Username,
                    CreatedAtUtc = now,
                    Verified = verified,
                });
            }
            await db.SaveChangesAsync(ct);
        }
        await _audit.RecordAsync(user, AuditActions.MemberAdd, group.Name,
            detail: verified ? $"{username} as {role}" : $"{username} as {role} (unverified: directory not available)",
            groupId: groupId);
        return new MemberAdded(username, storedDisplayName, verified);
    }

    public async Task SetMemberRoleAsync(UserContext user, Guid groupId, string username, GroupRole role, CancellationToken ct = default)
    {
        username = username.Trim().ToLowerInvariant();
        await _sessions.RequireLiveAsync(user, ct);
        Group group;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            // The caller's admin rights, the last-admin rule and the write are one
            // atomic step. Checked separately, two admins demoting each other at
            // the same moment would each still see the other in place, and both
            // would succeed — leaving the group with no admin at all.
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            group = await RequireGroupAdminAsync(db, user, groupId, ct);

            var member = await db.GroupMembers
                .SingleOrDefaultAsync(m => m.GroupId == groupId && m.Username == username && !m.IsDeleted, ct)
                ?? throw new VaultNotFoundException($"'{username}' is not a member of this group.");

            if (member.Role == GroupRole.Admin && role != GroupRole.Admin)
            {
                await EnsureNotLastAdminAsync(db, groupId, username, ct);
            }
            member.Role = role;
            await db.SaveChangesAsync(ct);
        }
        await _audit.RecordAsync(user, AuditActions.MemberRole, group.Name,
            detail: $"{username} → {role}", groupId: groupId);
    }

    public async Task RemoveMemberAsync(UserContext user, Guid groupId, string username, CancellationToken ct = default)
    {
        username = username.Trim().ToLowerInvariant();
        await _sessions.RequireLiveAsync(user, ct);
        Group group;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            // Atomic for the same reason as SetMemberRoleAsync.
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            group = await RequireGroupAdminAsync(db, user, groupId, ct);

            var member = await db.GroupMembers
                .SingleOrDefaultAsync(m => m.GroupId == groupId && m.Username == username && !m.IsDeleted, ct)
                ?? throw new VaultNotFoundException($"'{username}' is not a member of this group.");

            if (member.Role == GroupRole.Admin)
            {
                await EnsureNotLastAdminAsync(db, groupId, username, ct);
            }
            member.IsDeleted = true;
            await db.SaveChangesAsync(ct);
        }
        await _audit.RecordAsync(user, AuditActions.MemberRemove, group.Name,
            detail: username, groupId: groupId);
    }

    /// <summary>
    /// Live groups that currently have no admin; site admins only. The last-admin
    /// rule holds within a site, but two DISCONNECTED sites can each demote (or
    /// remove) the other's admin, and the merge keeps both changes because they
    /// touch different membership rows. Harpo deliberately does not pick a new
    /// admin on its own — silently promoting someone in a password manager is a
    /// privilege escalation nobody decided on — so the policy is: the group keeps
    /// working for its members, it is listed here, and a site administrator
    /// appoints an admin (which then replicates like any other change).
    /// </summary>
    public async Task<List<Group>> GetGroupsWithoutAdminAsync(UserContext user, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site administrators can do that.");
        }
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var groupsWithAdmin = db.GroupMembers
            .Where(m => !m.IsDeleted && m.Role == GroupRole.Admin)
            .Select(m => m.GroupId);
        return await db.Groups
            .Where(g => !g.IsDeleted && g.OwnerUsername == "" && !groupsWithAdmin.Contains(g.Id))
            .OrderBy(g => g.Name)
            .ToListAsync(ct);
    }

    // ---- personal vaults ----

    /// <summary>The name every personal vault carries while it is one.</summary>
    public const string PersonalVaultName = "Personal";

    /// <summary>
    /// The user's personal vault, created on first use. Its id is derived from
    /// the username, so two sites that first see the same person while out of
    /// contact create the same row and merge instead of giving them two vaults.
    /// A vault that was taken over (see <see cref="TakeOverPersonalVaultAsync"/>)
    /// has become an ordinary group under that id, so the next one takes the
    /// next derived id.
    /// </summary>
    public async Task<Group> EnsurePersonalVaultAsync(UserContext user, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        // "Does it exist?" and the insert are one step: two pages of the same
        // person opening at once must not both try to create it.
        using var gate = await db.BeginExclusiveWriteAsync(ct);

        // Newest first: for a moment after a takeover elsewhere, a site can hold
        // the owner's old vault (not yet seen as taken over) beside the new one.
        var existing = await db.Groups
            .Where(g => !g.IsDeleted && g.OwnerUsername == user.Username)
            .OrderByDescending(g => g.CreatedAtUtc)
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
        {
            return existing;
        }

        var now = _time.GetUtcNow().UtcDateTime;
        var group = new Group
        {
            Id = await NextPersonalVaultIdAsync(db, user.Username, ct),
            Name = PersonalVaultName,
            Description = "",
            CreatedBy = user.Username,
            CreatedAtUtc = now,
            OwnerUsername = user.Username,
        };
        db.Groups.Add(group);
        db.GroupMembers.Add(new GroupMember
        {
            Id = DeterministicGuid.For(group.Id.ToString("N"), user.Username),
            GroupId = group.Id,
            Username = user.Username,
            DisplayName = user.DisplayName,
            Role = GroupRole.Admin,
            AddedBy = user.Username,
            CreatedAtUtc = now,
            Verified = true, // the owner's own sign-in
        });
        await db.SaveChangesAsync(ct);
        return group;
    }

    private static async Task<Guid> NextPersonalVaultIdAsync(HarpoDbContext db, string username, CancellationToken ct)
    {
        for (var generation = 1; ; generation++)
        {
            var id = generation == 1
                ? DeterministicGuid.For("personal", username)
                : DeterministicGuid.For("personal", username, generation.ToString());
            if (!await db.Groups.AnyAsync(g => g.Id == id, ct))
            {
                return id;
            }
        }
    }

    /// <summary>Every live personal vault — owner and size only. Site admins only.</summary>
    public async Task<List<PersonalVaultSummary>> GetPersonalVaultsAsync(UserContext user, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site administrators can do that.");
        }
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var vaults = await db.Groups
            .Where(g => !g.IsDeleted && g.OwnerUsername != "")
            .OrderBy(g => g.OwnerUsername)
            .ToListAsync(ct);
        var ids = vaults.Select(g => g.Id).ToList();
        var entryCounts = await db.PasswordEntries
            .Where(e => !e.IsDeleted && ids.Contains(e.GroupId))
            .GroupBy(e => e.GroupId)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var displayNames = await db.GroupMembers
            .Where(m => ids.Contains(m.GroupId))
            .Select(m => new { m.GroupId, m.Username, m.DisplayName })
            .ToListAsync(ct);
        return vaults
            .Select(g => new PersonalVaultSummary(
                g,
                displayNames.FirstOrDefault(m => m.GroupId == g.Id && m.Username == g.OwnerUsername)?.DisplayName ?? g.OwnerUsername,
                entryCounts.GetValueOrDefault(g.Id)))
            .ToList();
    }

    /// <summary>
    /// Turns someone's personal vault into an ordinary group with the calling
    /// site admin as an admin of it — for when its owner has left and the
    /// company accounts they kept there must not be lost. The owner keeps their
    /// membership, so if they are still around they see exactly what happened,
    /// and the audit trail records it. Their next visit gives them a fresh,
    /// empty personal vault.
    /// </summary>
    public async Task<Group> TakeOverPersonalVaultAsync(UserContext user, Guid groupId, string name, CancellationToken ct = default)
    {
        if (!user.IsSiteAdmin)
        {
            throw new VaultAccessDeniedException("Only site administrators can take over a personal vault.");
        }

        await _sessions.RequireLiveAsync(user, ct);
        Group group;
        string owner;
        await using (var db = await _dbFactory.CreateDbContextAsync(ct))
        {
            using var gate = await db.BeginExclusiveWriteAsync(ct);
            group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
                ?? throw new VaultNotFoundException("Personal vault not found.");
            if (!group.IsPersonal)
            {
                throw new VaultValidationException("That is not a personal vault (it may have been taken over already).");
            }
            owner = group.OwnerUsername;
            name = name.Trim();
            group.Name = name.Length == 0 ? $"{owner}'s personal vault" : name;
            group.OwnerUsername = "";

            var now = _time.GetUtcNow().UtcDateTime;
            var membershipId = DeterministicGuid.For(groupId.ToString("N"), user.Username);
            var membership = await db.GroupMembers.SingleOrDefaultAsync(m => m.Id == membershipId, ct);
            if (membership is null)
            {
                db.GroupMembers.Add(new GroupMember
                {
                    Id = membershipId,
                    GroupId = groupId,
                    Username = user.Username,
                    DisplayName = user.DisplayName,
                    Role = GroupRole.Admin,
                    AddedBy = user.Username,
                    CreatedAtUtc = now,
                    Verified = true, // the site admin's own sign-in
                });
            }
            else
            {
                membership.IsDeleted = false;
                membership.Role = GroupRole.Admin;
                membership.AddedBy = user.Username;
                membership.CreatedAtUtc = now;
                membership.Verified = true;
            }
            await db.SaveChangesAsync(ct);
        }
        await _audit.RecordAsync(user, AuditActions.PersonalTakeover, group.Name,
            detail: $"was the personal vault of {owner}", groupId: groupId);
        return group;
    }

    /// <summary>
    /// A personal vault answers to its owner alone. This is checked before any
    /// role lookup, so neither site-admin rights nor a stray membership row
    /// opens it to anyone else.
    /// </summary>
    internal static void RequireNotSomeoneElsesPersonalVault(Group group, UserContext user)
    {
        if (group.IsPersonal && group.OwnerUsername != user.Username)
        {
            throw new VaultAccessDeniedException("Only its owner can open a personal vault.");
        }
    }

    /// <summary>Role of the user in the group, resolved fresh; null when not a member.</summary>
    public async Task<GroupRole?> GetMyRoleAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await _sessions.RequireLiveAsync(user, ct);
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await GetRoleAsync(db, groupId, user.Username, ct);
    }

    internal static async Task<GroupRole?> GetRoleAsync(HarpoDbContext db, Guid groupId, string username, CancellationToken ct)
    {
        var member = await db.GroupMembers
            .SingleOrDefaultAsync(m => m.GroupId == groupId && m.Username == username && !m.IsDeleted, ct);
        return member?.Role;
    }

    private async Task<Group> RequireGroupAdminAsync(HarpoDbContext db, UserContext user, Guid groupId, CancellationToken ct)
    {
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
        RequireNotSomeoneElsesPersonalVault(group, user);
        if (group.IsPersonal)
        {
            // Nothing about a personal vault is managed: no name, no members,
            // no deletion — not even by its owner. The entries inside are.
            throw new VaultAccessDeniedException("A personal vault has no settings or members to manage.");
        }
        if (user.IsSiteAdmin)
        {
            return group;
        }
        var role = await GetRoleAsync(db, groupId, user.Username, ct);
        if (role != GroupRole.Admin)
        {
            throw new VaultAccessDeniedException("Only group admins can do that.");
        }
        return group;
    }

    private static async Task EnsureNotLastAdminAsync(HarpoDbContext db, Guid groupId, string exceptUsername, CancellationToken ct)
    {
        var otherAdmins = await db.GroupMembers.AnyAsync(
            m => m.GroupId == groupId && !m.IsDeleted && m.Role == GroupRole.Admin && m.Username != exceptUsername, ct);
        if (!otherAdmins)
        {
            throw new VaultValidationException("A group must keep at least one admin.");
        }
    }
}
