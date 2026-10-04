using System.Security.Claims;
using System.Threading.RateLimiting;
using Harpo.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Harpo.Tests;

public class InteractiveConnectionsTests
{
    private static DefaultHttpContext Request(string path, string? user = null, IServiceProvider? services = null)
    {
        var context = new DefaultHttpContext { Response = { Body = new MemoryStream() } };
        context.Request.Path = path;
        if (user is not null)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, user)], "test"));
        }
        if (services is not null)
        {
            context.RequestServices = services;
        }
        return context;
    }

    [Theory]
    [InlineData("/_blazor", true)]
    [InlineData("/_blazor/negotiate", true)]
    [InlineData("/_blazor/disconnect", true)]
    [InlineData("/_blazor/initializers", false)] // fetched by every page's boot script, the login page included
    [InlineData("/_framework/blazor.web.js", false)]
    [InlineData("/_blazorish", false)]
    [InlineData("/login", false)]
    [InlineData("/", false)]
    public void Only_the_circuit_endpoint_counts_as_a_connection(string path, bool expected)
    {
        Assert.Equal(expected, InteractiveConnections.IsCircuitRequest(path));
    }

    [Fact]
    public async Task One_account_is_capped_while_others_and_ordinary_requests_are_not()
    {
        using var limiter = InteractiveConnections.CreateLimiter(new ConnectionLimitOptions { MaxPerUser = 3 });

        var held = new List<RateLimitLease>();
        for (var i = 0; i < 3; i++)
        {
            var lease = await limiter.AcquireAsync(Request("/_blazor", "alice"));
            Assert.True(lease.IsAcquired);
            held.Add(lease);
        }

        using (var fourth = await limiter.AcquireAsync(Request("/_blazor", "alice")))
        {
            Assert.False(fourth.IsAcquired);
        }
        using (var sameAccount = await limiter.AcquireAsync(Request("/_blazor/negotiate", "ALICE")))
        {
            Assert.False(sameAccount.IsAcquired); // one account, however its name is typed
        }
        using (var someoneElse = await limiter.AcquireAsync(Request("/_blazor", "bob")))
        {
            Assert.True(someoneElse.IsAcquired);
        }
        using (var ordinaryPage = await limiter.AcquireAsync(Request("/vault", "alice")))
        {
            Assert.True(ordinaryPage.IsAcquired); // only connections are counted, never page loads
        }

        // Closing a tab frees its slot.
        held[0].Dispose();
        using (var afterClosing = await limiter.AcquireAsync(Request("/_blazor", "alice")))
        {
            Assert.True(afterClosing.IsAcquired);
        }
        held.ForEach(lease => lease.Dispose());
    }

    [Fact]
    public async Task Zero_removes_the_limit()
    {
        using var limiter = InteractiveConnections.CreateLimiter(new ConnectionLimitOptions { MaxPerUser = 0 });
        var leases = new List<RateLimitLease>();
        for (var i = 0; i < 200; i++)
        {
            leases.Add(await limiter.AcquireAsync(Request("/_blazor", "alice")));
        }
        Assert.All(leases, lease => Assert.True(lease.IsAcquired));
        leases.ForEach(lease => lease.Dispose());
    }

    [Fact]
    public async Task Without_a_session_the_circuit_endpoint_is_refused_and_everything_else_passes()
    {
        var (pipeline, services, reached) = Pipeline(maxPerUser: 5, _ => Task.CompletedTask);

        foreach (var path in new[] { "/_blazor", "/_blazor/negotiate", "/_blazor/disconnect" })
        {
            var refused = Request(path, user: null, services);
            await pipeline(refused);
            Assert.Equal(StatusCodes.Status401Unauthorized, refused.Response.StatusCode);
        }
        Assert.Empty(reached);

        foreach (var path in new[] { "/_blazor/initializers", "/login", "/_framework/blazor.web.js" })
        {
            var passed = Request(path, user: null, services);
            await pipeline(passed);
            Assert.Equal(StatusCodes.Status200OK, passed.Response.StatusCode);
        }
        Assert.Equal(3, reached.Count);

        var signedIn = Request("/_blazor/negotiate", "alice", services);
        await pipeline(signedIn);
        Assert.Equal(StatusCodes.Status200OK, signedIn.Response.StatusCode);
    }

    [Fact]
    public async Task A_connection_over_the_limit_gets_429_until_one_closes()
    {
        // The endpoint stands in for an open WebSocket: it does not return until released.
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var (pipeline, services, reached) = Pipeline(maxPerUser: 2, _ => release.Task);

        var open = new[] { pipeline(Request("/_blazor", "alice", services)), pipeline(Request("/_blazor", "alice", services)) };
        await WaitUntil(() => reached.Count == 2);

        var third = Request("/_blazor", "alice", services);
        await pipeline(third);
        Assert.Equal(StatusCodes.Status429TooManyRequests, third.Response.StatusCode);
        Assert.Equal(2, reached.Count);

        release.SetResult();
        await Task.WhenAll(open);

        var afterClosing = Request("/_blazor", "alice", services);
        await pipeline(afterClosing);
        Assert.Equal(StatusCodes.Status200OK, afterClosing.Response.StatusCode);
    }

    private static (RequestDelegate Pipeline, IServiceProvider Services, List<string> Reached) Pipeline(
        int maxPerUser, RequestDelegate endpoint)
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddMetrics()
            .AddInteractiveConnectionLimits(new ConnectionLimitOptions { MaxPerUser = maxPerUser })
            .BuildServiceProvider();
        var reached = new List<string>();
        var app = new ApplicationBuilder(services);
        app.UseInteractiveConnectionLimits();
        app.Run(context =>
        {
            lock (reached)
            {
                reached.Add(context.Request.Path);
            }
            return endpoint(context);
        });
        return (app.Build(), services, reached);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            await Task.Delay(25);
        }
        Assert.True(condition(), "condition was not reached in time");
    }
}
