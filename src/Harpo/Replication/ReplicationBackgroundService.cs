using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace Harpo.Replication;

/// <summary>
/// Pull loop: every IntervalSeconds, asks each configured peer for rows newer than
/// our high-watermark vector and merges them. Pulling (rather than pushing) keeps
/// each site in charge of its own ingest and makes the topology easy to reason
/// about; because rows carry their origin site, changes also flow transitively
/// through intermediate sites, so a full mesh is not required.
/// </summary>
public class ReplicationBackgroundService : BackgroundService
{
    private const int MaxRoundsPerCycle = 50;

    private readonly ReplicationEngine _engine;
    private readonly ReplicationOptions _options;
    private readonly ReplicationStatusTracker _tracker;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ReplicationBackgroundService> _logger;

    public ReplicationBackgroundService(
        ReplicationEngine engine,
        IOptions<ReplicationOptions> options,
        ReplicationStatusTracker tracker,
        IHttpClientFactory httpClientFactory,
        ILogger<ReplicationBackgroundService> logger)
    {
        _engine = engine;
        _options = options.Value;
        _tracker = tracker;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled || _options.Peers.Count == 0)
        {
            _logger.LogInformation("Replication is disabled (no key or no peers configured).");
            return;
        }

        _logger.LogInformation("Replication enabled: site {SiteId}, {PeerCount} peer(s), every {Interval}s",
            _engine.SiteId, _options.Peers.Count, _options.IntervalSeconds);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(2, _options.IntervalSeconds)));
        do
        {
            foreach (var peer in _options.Peers)
            {
                try
                {
                    await SyncPeerAsync(peer, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    var status = _tracker.GetOrAdd(peer.Name, peer.Url);
                    status.LastAttemptUtc = DateTime.UtcNow;
                    status.LastError = ex.Message;
                    _logger.LogWarning("Sync with peer {Peer} failed: {Error}", peer.Name, ex.Message);
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    private async Task SyncPeerAsync(ReplicationOptions.Peer peer, CancellationToken ct)
    {
        var status = _tracker.GetOrAdd(peer.Name, peer.Url);
        status.LastAttemptUtc = DateTime.UtcNow;

        using var client = _httpClientFactory.CreateClient("harpo-replication");
        client.BaseAddress = new Uri(peer.Url.TrimEnd('/') + "/");
        client.DefaultRequestHeaders.Add(ReplicationEndpoints.KeyHeader, _options.Key);

        var pulledThisCycle = 0;
        for (var round = 0; round < MaxRoundsPerCycle; round++)
        {
            var request = new PullRequest
            {
                SiteId = _engine.SiteId,
                Vector = await _engine.GetVectorAsync(ct),
            };
            using var httpResponse = await client.PostAsJsonAsync("api/replication/pull", request, ct);
            httpResponse.EnsureSuccessStatusCode();
            var response = await httpResponse.Content.ReadFromJsonAsync<PullResponse>(ct)
                ?? throw new InvalidOperationException("Peer returned an empty response.");

            if (response.UtcNow != default)
            {
                status.ClockSkew = response.UtcNow - DateTime.UtcNow;
            }

            if (response.RowCount > 0)
            {
                await _engine.ApplyAsync(response, ct);
                pulledThisCycle += response.RowCount;
            }
            if (!response.HasMore)
            {
                break;
            }
        }

        status.LastSuccessUtc = DateTime.UtcNow;
        status.LastError = null;
        status.LastPulledRows = pulledThisCycle;
        status.TotalPulledRows += pulledThisCycle;
    }
}
