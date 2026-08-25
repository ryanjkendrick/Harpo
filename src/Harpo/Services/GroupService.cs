using Harpo.Data;
using Microsoft.EntityFrameworkCore;

namespace Harpo.Services;

public sealed record GroupSummary(Group Group, GroupRole? MyRole, int MemberCount, int EntryCount);

/// <summary>
/// Group and membership management. Authorization model:
///  - any authenticated user may create a group and becomes its admin;
///  - group members see the group and its passwords;
///  - group admins additionally manage members and the group itself;
///  - site admins (from the AD admin group) can do everything.
/// All checks live here, server-side — the UI only hides buttons.
/// </summary>
public class GroupService
{
    private readonly IDbContextFactory<HarpoDbContext> _dbFactory;
    private readonly TimeProvider _time;

    public GroupService(IDbContextFactory<HarpoDbContext> dbFactory, TimeProvider time)
    {
        _dbFactory = dbFactory;
        _time = time;
    }

    public async Task<List<GroupSummary>> GetMyGroupsAsync(UserContext user, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var memberships = await db.GroupMembers
            .Where(m => !m.IsDeleted && m.Username == user.Username)
            .ToDictionaryAsync(m => m.GroupId, m => m.Role, ct);

        var groupsQuery = db.Groups.Where(g => !g.IsDeleted);
        if (!user.IsSiteAdmin)
        {
            var groupIds = memberships.Keys.ToList();
            groupsQuery = groupsQuery.Where(g => groupIds.Contains(g.Id));
        }
        var groups = await groupsQuery.OrderBy(g => g.Name).ToListAsync(ct);

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

    public async Task<Group> CreateGroupAsync(UserContext user, string name, string description, CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            throw new VaultValidationException("Group name is required.");
        }

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
        });
        await db.SaveChangesAsync(ct);
        return group;
    }

    public async Task<(Group Group, GroupRole? MyRole)> GetGroupAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await db.Groups.SingleOrDefaultAsync(g => g.Id == groupId && !g.IsDeleted, ct)
            ?? throw new VaultNotFoundException("Group not found.");
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
            throw new VaultValidationException("Group name is required.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await RequireGroupAdminAsync(db, user, groupId, ct);
        group.Name = name;
        group.Description = description.Trim();
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteGroupAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var group = await RequireGroupAdminAsync(db, user, groupId, ct);
        group.IsDeleted = true;
        await db.SaveChangesAsync(ct);
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

    public async Task AddMemberAsync(UserContext user, Guid groupId, string username, string displayName, GroupRole role, CancellationToken ct = default)
    {
        username = username.Trim().ToLowerInvariant();
        if (username.Length == 0)
        {
            throw new VaultValidationException("Username is required.");
        }

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireGroupAdminAsync(db, user, groupId, ct);

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
        }
        else
        {
            db.GroupMembers.Add(new GroupMember
            {
                Id = id,
                GroupId = groupId,
                Username = username,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
                Role = role,
                AddedBy = user.Username,
                CreatedAtUtc = now,
            });
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task SetMemberRoleAsync(UserContext user, Guid groupId, string username, GroupRole role, CancellationToken ct = default)
    {
        username = username.Trim().ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireGroupAdminAsync(db, user, groupId, ct);

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

    public async Task RemoveMemberAsync(UserContext user, Guid groupId, string username, CancellationToken ct = default)
    {
        username = username.Trim().ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        await RequireGroupAdminAsync(db, user, groupId, ct);

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

    /// <summary>Role of the user in the group, resolved fresh; null when not a member.</summary>
    public async Task<GroupRole?> GetMyRoleAsync(UserContext user, Guid groupId, CancellationToken ct = default)
    {
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
