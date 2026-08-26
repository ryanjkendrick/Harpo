namespace Harpo.Services;

/// <summary>
/// Matches entry URLs against icon attributions. Attributions are hostnames;
/// a URL matches when its host equals an attributed host or is a subdomain of
/// one ("git.gitlab.com" matches "gitlab.com"). Between several matching
/// icons, the longest (most specific) attributed host wins.
/// </summary>
public static class IconUrlMatcher
{
    /// <summary>Host of whatever the user typed, tolerant of missing schemes and trailing paths. Null when unparseable.</summary>
    public static string? ExtractHost(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }
        var candidate = url.Trim();
        if (!candidate.Contains("://", StringComparison.Ordinal))
        {
            candidate = "https://" + candidate;
        }
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)
            || uri.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6)
            || uri.Host.Length == 0
            || !uri.Host.Contains('.'))
        {
            return null;
        }
        return uri.Host.ToLowerInvariant();
    }

    /// <summary>
    /// Turns free-form input ("https://gitlab.com/x, GIT.corp.io") into the
    /// canonical space-separated host list stored on the icon.
    /// </summary>
    public static string NormalizeHostList(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return "";
        }
        var hosts = input
            .Split([' ', ',', ';', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries)
            .Select(ExtractHost)
            .Where(h => h is not null)
            .Select(h => h!)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();
        return string.Join(' ', hosts);
    }

    /// <summary>True when <paramref name="host"/> is the attributed host or one of its subdomains.</summary>
    public static bool HostMatches(string host, string attributed) =>
        host.Equals(attributed, StringComparison.OrdinalIgnoreCase)
        || host.EndsWith("." + attributed, StringComparison.OrdinalIgnoreCase);

    /// <summary>The best icon for a URL, or null. Ties break on the longest attributed host, then name.</summary>
    public static IconSummary? FindBestMatch(string? url, IEnumerable<IconSummary> icons)
    {
        var host = ExtractHost(url);
        if (host is null)
        {
            return null;
        }
        IconSummary? best = null;
        var bestLength = -1;
        foreach (var icon in icons)
        {
            foreach (var attributed in icon.MatchUrls.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (HostMatches(host, attributed) && attributed.Length > bestLength)
                {
                    best = icon;
                    bestLength = attributed.Length;
                }
            }
        }
        return best;
    }
}
