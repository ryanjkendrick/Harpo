namespace Harpo.Components.Shared;

/// <summary>
/// Page arithmetic for lists the page already holds in full (members, icons,
/// personal vaults, groups): only the page shown is drawn.
/// </summary>
public static class Paging
{
    public static int PageCount(int total, int pageSize) => Math.Max(1, (total + pageSize - 1) / pageSize);

    /// <summary>
    /// The items on <paramref name="page"/>. The page is first pulled back inside
    /// the list, which a filter or a removal may have shortened.
    /// </summary>
    public static List<T> Slice<T>(IReadOnlyList<T> items, ref int page, int pageSize)
    {
        page = Math.Clamp(page, 1, PageCount(items.Count, pageSize));
        return items.Skip((page - 1) * pageSize).Take(pageSize).ToList();
    }

    /// <summary>The page that holds the item at <paramref name="index"/> (0-based).</summary>
    public static int PageOf(int index, int pageSize) => index < 0 ? 1 : index / pageSize + 1;
}
