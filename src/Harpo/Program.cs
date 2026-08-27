using Harpo;
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

// We ship the SQLCipher build of SQLite (optional full-file encryption via
// Harpo:DatabaseKey); with the Sqlite.Core packages the provider must be
// initialized explicitly before any database use.
SQLitePCL.Batteries_V2.Init();

var builder = WebApplication.CreateBuilder(args);

// Any config value may be supplied via a file (Docker/K8s secrets):
// <Key>__File=/run/secrets/... — see FileConfigurationSecrets.
FileConfigurationSecrets.ApplyFileIndirection(builder.Configuration);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();

// ---- Options ----
builder.Services.Configure<SiteOptions>(builder.Configuration.GetSection("Harpo"));
builder.Services.Configure<Harpo.Offline.OfflineOptions>(builder.Configuration.GetSection("Harpo:Offline"));
builder.Services.Configure<AuditOptions>(builder.Configuration.GetSection("Harpo:Audit"));
builder.Services.Configure<HealthOptions>(builder.Configuration.GetSection("Harpo:Health"));
builder.Services.Configure<IconOptions>(builder.Configuration.GetSection("Harpo:Icons"));
builder.Services.Configure<ReplicationOptions>(builder.Configuration.GetSection("Replication"));
builder.Services.Configure<LdapOptions>(builder.Configuration.GetSection("Auth:Ldap"));
builder.Services.Configure<DevAuthOptions>(builder.Configuration.GetSection("Auth"));
builder.Services.Configure<LoginThrottleOptions>(builder.Configuration.GetSection("Auth:Lockout"));

// ---- Data ----
var rawConnectionString = builder.Configuration.GetConnectionString("Harpo") ?? "Data Source=harpo.db";
var dbEncryption = DbEncryptionOptions.FromConfiguration(builder.Configuration);
var connectionString = DbEncryption.ApplyKey(rawConnectionString, dbEncryption);
builder.Services.AddDbContextFactory<HarpoDbContext>(options => options.UseSqlite(connectionString));
builder.Services.AddSingleton(TimeProvider.System);

// ---- Domain services ----
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<CryptoService>();
builder.Services.AddSingleton<AuditService>();
builder.Services.AddHostedService<AuditRetentionService>();
builder.Services.AddSingleton<GroupService>();
builder.Services.AddSingleton<VaultService>();
builder.Services.AddSingleton<HealthService>();
builder.Services.AddSingleton<IconService>();
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

builder.Services.AddSingleton<LoginThrottle>();

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

// Encrypt / rekey / decrypt the database file to match configuration, then init.
await DbEncryption.EnsureEncryptionStateAsync(rawConnectionString, dbEncryption, app.Logger);
await DbInitializer.InitializeAsync(
    app.Services.GetRequiredService<IDbContextFactory<HarpoDbContext>>(), connectionString, app.Logger);

// Validate the master key against the stored data (fail fast on a wrong key),
// and re-encrypt local data when a key rotation is in progress.
await KeyRotation.EnsureMasterKeyStateAsync(
    app.Services.GetRequiredService<IDbContextFactory<HarpoDbContext>>(),
    app.Services.GetRequiredService<CryptoService>(),
    app.Services.GetRequiredService<AuditService>(),
    app.Logger);

// Server-level icon catalogue: import whatever the admin mounted into the icons folder.
await app.Services.GetRequiredService<IconService>().ImportFromDirectoryAsync();

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

// Catalogue icons. Immutable per id, so clients may cache hard. The headers
// neuter scripted SVGs even when the URL is opened directly.
app.MapGet("/api/icons/{id:guid}", async (Guid id, IconService icons, HttpContext http, CancellationToken ct) =>
{
    var icon = await icons.GetDataAsync(id, ct);
    if (icon is null)
    {
        return Results.NotFound();
    }
    http.Response.Headers.ContentSecurityPolicy = "sandbox; default-src 'none'";
    http.Response.Headers.XContentTypeOptions = "nosniff";
    http.Response.Headers.CacheControl = "private, max-age=86400, immutable";
    return Results.File(icon.Value.Data, icon.Value.ContentType);
}).RequireAuthorization();

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
