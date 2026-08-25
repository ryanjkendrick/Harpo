using Harpo.Components;
using Harpo.Data;
using Harpo.Offline;
using Harpo.Replication;
using Harpo.Security;
using Harpo.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();

// ---- Options ----
builder.Services.Configure<SiteOptions>(builder.Configuration.GetSection("Harpo"));
builder.Services.Configure<Harpo.Offline.OfflineOptions>(builder.Configuration.GetSection("Harpo:Offline"));
builder.Services.Configure<ReplicationOptions>(builder.Configuration.GetSection("Replication"));
builder.Services.Configure<LdapOptions>(builder.Configuration.GetSection("Auth:Ldap"));
builder.Services.Configure<DevAuthOptions>(builder.Configuration.GetSection("Auth"));

// ---- Data ----
var connectionString = builder.Configuration.GetConnectionString("Harpo") ?? "Data Source=harpo.db";
builder.Services.AddDbContextFactory<HarpoDbContext>(options => options.UseSqlite(connectionString));
builder.Services.AddSingleton(TimeProvider.System);

// ---- Domain services ----
builder.Services.AddSingleton<CryptoService>();
builder.Services.AddSingleton<GroupService>();
builder.Services.AddSingleton<VaultService>();
builder.Services.AddSingleton<Harpo.Offline.OfflineSnapshotThrottle>();

// ---- Authentication: LDAP bind against Active Directory (or dev users for local testing) ----
var authMode = builder.Configuration["Auth:Mode"] ?? "Ldap";
var devAuth = authMode.Equals("Development", StringComparison.OrdinalIgnoreCase);
if (devAuth)
{
    builder.Services.AddSingleton<IAuthenticator, DevAuthenticator>();
}
else
{
    builder.Services.AddSingleton<IAuthenticator, LdapAuthenticator>();
}

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = ".harpo.auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/denied";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization();

// Cookie/antiforgery keys must survive container restarts.
var keysPath = builder.Configuration["Harpo:DataProtectionKeysPath"];
if (!string.IsNullOrWhiteSpace(keysPath))
{
    Directory.CreateDirectory(keysPath);
    builder.Services.AddDataProtection()
        .SetApplicationName("Harpo")
        .PersistKeysToFileSystem(new DirectoryInfo(keysPath));
}

// ---- Cross-site replication ----
builder.Services.AddHttpClient("harpo-replication", client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddSingleton<ReplicationEngine>();
builder.Services.AddSingleton<ReplicationStatusTracker>();
builder.Services.AddHostedService<ReplicationBackgroundService>();

var app = builder.Build();

// Fail fast on bad configuration (missing master key, missing LDAP server, ...).
_ = app.Services.GetRequiredService<CryptoService>();
_ = app.Services.GetRequiredService<IAuthenticator>();
if (devAuth)
{
    app.Logger.LogWarning(
        "AUTH IS IN DEVELOPMENT MODE — users come from Auth:DevUsers in configuration. " +
        "Never use this outside local testing; set Auth:Mode=Ldap for Active Directory.");
}

await DbInitializer.InitializeAsync(
    app.Services.GetRequiredService<IDbContextFactory<HarpoDbContext>>(), connectionString);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapReplicationEndpoints();
app.MapOfflineEndpoints();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).AllowAnonymous();

app.MapPost("/logout", async (HttpContext context, IAntiforgery antiforgery) =>
{
    try
    {
        await antiforgery.ValidateRequestAsync(context);
    }
    catch (AntiforgeryValidationException)
    {
        return Results.BadRequest();
    }
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.LocalRedirect("/login");
}).AllowAnonymous();

app.Run();
