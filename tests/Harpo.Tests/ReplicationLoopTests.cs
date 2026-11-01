using System.Net;
using System.Net.Http.Json;
using Harpo.Replication;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Harpo.Tests;

/// <summary>
/// The background pull loop itself, against stub peers: what one peer's trouble
/// does to the others.
/// </summary>
public class ReplicationLoopTests
{
    // A link that drops packets gives no answer and no error: the request just
    // waits until the HTTP timeout. Every other peer answers at once, with nothing new.
    private sealed class StubPeers : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.Host == "silent")
            {
                await Task.Delay(Timeout.Infinite, ct);
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new PullResponse { SiteId = request.RequestUri.Host, UtcNow = DateTime.UtcNow }),
            };
        }
    }

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        // Same timeout as the real "harpo-replication" client.
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(30) };
    }

    [Fact]
    public async Task A_peer_that_never_answers_does_not_hold_up_the_others()
    {
        using var site = new TestSite("alpha");
        var options = Options.Create(new ReplicationOptions
        {
            Key = "test-key",
            IntervalSeconds = 2,
            // The silent peer first: a loop that visits peers in turn waits on it before asking beta.
            Peers =
            {
                new ReplicationOptions.Peer { Name = "silent", Url = "http://silent" },
                new ReplicationOptions.Peer { Name = "beta", Url = "http://beta" },
            },
        });
        var tracker = new ReplicationStatusTracker();
        using var handler = new StubPeers();
        using var service = new ReplicationBackgroundService(site.Engine, options, tracker, new StubFactory(handler),
            NullLogger<ReplicationBackgroundService>.Instance);

        await service.StartAsync(CancellationToken.None);
        try
        {
            var beta = tracker.GetOrAdd("beta", "http://beta");
            var silent = tracker.GetOrAdd("silent", "http://silent");
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (beta.LastSuccessUtc is null && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50);
            }
            var first = beta.LastSuccessUtc;
            Assert.NotNull(first);
            // And beta keeps its own pace: a second cycle about IntervalSeconds later.
            while (beta.LastSuccessUtc == first && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50);
            }
            Assert.True(beta.LastSuccessUtc > first, "beta was synced once, then not again while the silent peer was waiting");
            // All the while the silent peer's first request is still out.
            Assert.Null(silent.LastSuccessUtc);
            Assert.Null(silent.LastError);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }
}
