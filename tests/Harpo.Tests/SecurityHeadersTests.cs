using System.Text.RegularExpressions;
using Harpo.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Harpo.Tests;

public class SecurityHeadersTests
{
    private static Dictionary<string, string> Directives(string policy) =>
        policy.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(d => d.Split(' ', 2))
            .ToDictionary(parts => parts[0], parts => parts.Length > 1 ? parts[1] : "");

    [Fact]
    public void App_policy_allows_nothing_inline_and_nothing_foreign()
    {
        var policy = SecurityHeaders.AppPolicy(new HostString("harpo.corp.example"));
        var directives = Directives(policy);

        Assert.Equal("'self'", directives["default-src"]);
        Assert.Equal("'self'", directives["script-src"]);
        Assert.Equal("'self'", directives["style-src"]);
        Assert.Equal("'self' data:", directives["img-src"]);
        Assert.Equal("'none'", directives["object-src"]);
        Assert.Equal("'self'", directives["base-uri"]);
        Assert.Equal("'self'", directives["form-action"]);
        Assert.Equal("'none'", directives["frame-ancestors"]);

        // No escape hatches anywhere in it.
        Assert.DoesNotContain("unsafe", policy);
        Assert.DoesNotContain("*", policy);
        Assert.DoesNotContain("http:", policy);
        Assert.DoesNotContain("https:", policy);
    }

    [Theory]
    [InlineData("harpo.corp.example")]
    [InlineData("localhost:8081")]
    [InlineData("10.0.0.7:8443")]
    [InlineData("[::1]:8080")]
    public void App_policy_names_this_hosts_websocket_origin(string host)
    {
        var connect = Directives(SecurityHeaders.AppPolicy(new HostString(host)))["connect-src"];
        Assert.Equal($"'self' ws://{host} wss://{host}", connect);
    }

    [Theory]
    [InlineData("")]
    [InlineData("harpo.example; script-src *")]
    [InlineData("harpo.example 'unsafe-inline'")]
    [InlineData("harpo.example\r\nX-Injected: 1")]
    [InlineData("-leading.example")]
    [InlineData("harpo.example:notaport")]
    public void A_host_that_is_not_plain_host_syntax_is_never_echoed(string host)
    {
        var policy = SecurityHeaders.AppPolicy(new HostString(host));
        Assert.Equal("'self'", Directives(policy)["connect-src"]);
        Assert.DoesNotContain("unsafe", policy);
        Assert.DoesNotContain("\n", policy);
    }

    [Fact]
    public void Offline_page_policy_matches_the_one_written_into_the_page()
    {
        // The page carries its policy in a meta tag (for copies a service worker
        // cached before the header existed). Two copies of a policy drift apart
        // unless something holds them together: this does.
        var html = File.ReadAllText(Path.Combine(RepoRoot(), "src", "Harpo", "wwwroot", "offline.html"));
        var meta = Regex.Match(html, "http-equiv=\"Content-Security-Policy\"\\s+content=\"([^\"]+)\"");
        Assert.True(meta.Success, "offline.html no longer declares a Content-Security-Policy meta tag");
        Assert.Equal(SecurityHeaders.OfflinePagePolicy, meta.Groups[1].Value);
    }

    [Fact]
    public async Task Every_response_gets_the_policy_and_the_offline_page_gets_its_own()
    {
        var pipeline = Pipeline(_ => Task.CompletedTask);

        var page = await Send(pipeline, "/vault/3f2c", "harpo.corp.example");
        Assert.Equal(SecurityHeaders.AppPolicy(new HostString("harpo.corp.example")), page.Response.Headers.ContentSecurityPolicy.ToString());
        Assert.Equal("nosniff", page.Response.Headers.XContentTypeOptions.ToString());

        var offline = await Send(pipeline, "/offline.html", "harpo.corp.example");
        Assert.Equal(SecurityHeaders.OfflinePagePolicy, offline.Response.Headers.ContentSecurityPolicy.ToString());
        Assert.Equal("nosniff", offline.Response.Headers.XContentTypeOptions.ToString());
    }

    [Fact]
    public async Task An_endpoint_with_a_stricter_policy_of_its_own_keeps_it()
    {
        // What the icon endpoint does: it sandboxes whatever image it serves.
        var pipeline = Pipeline(context =>
        {
            context.Response.Headers.ContentSecurityPolicy = "sandbox; default-src 'none'";
            return Task.CompletedTask;
        });

        var icon = await Send(pipeline, "/api/icons/0b7b0c0e", "harpo.corp.example");
        Assert.Equal("sandbox; default-src 'none'", icon.Response.Headers.ContentSecurityPolicy.ToString());
    }

    private static RequestDelegate Pipeline(RequestDelegate endpoint)
    {
        var app = new ApplicationBuilder(new ServiceCollection().BuildServiceProvider());
        app.UseSecurityHeaders();
        app.Run(endpoint);
        return app.Build();
    }

    private static async Task<HttpContext> Send(RequestDelegate pipeline, string path, string host)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Host = new HostString(host);
        await pipeline(context);
        return context;
    }

    internal static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Harpo.slnx")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("Could not find the repository root from " + AppContext.BaseDirectory);
    }
}
