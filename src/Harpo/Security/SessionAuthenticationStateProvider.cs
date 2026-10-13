using System.Security.Claims;
using Harpo.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Server.Circuits;

namespace Harpo.Security;

/// <summary>
/// An open interactive page keeps the user it signed in with for as long as it
/// stays open; its connection never passes the cookie check again. Every
/// <see cref="RevalidationInterval"/> this asks whether the page's session still
/// exists, and when it does not, the page's user becomes anonymous and
/// <c>SessionWatch</c> (on every interactive page) sends the browser to the
/// sign-in page, so nothing that was on screen stays there.
///
/// This is the tidy-up, not the guard: between two checks a page could still
/// ask for a secret, which is why the services check the session on every
/// reveal and write as well (<see cref="SessionService.RequireLiveAsync"/>).
/// </summary>
public sealed class SessionAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
{
    private readonly SessionService _sessions;
    private readonly CircuitConnection _connection;

    public SessionAuthenticationStateProvider(
        ILoggerFactory loggerFactory, SessionService sessions, CircuitConnection connection)
        : base(loggerFactory)
    {
        _sessions = sessions;
        _connection = connection;
    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromSeconds(30);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        var user = authenticationState.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            return true;
        }
        if (!_connection.IsUp)
        {
            // A page the browser has left (or lost) is kept on the server for a
            // few minutes in case it reconnects. There is no browser to send to
            // the sign-in page, so check again once it is back; until then it
            // can do nothing, and the services refuse it anyway.
            return true;
        }
        // Not activity: an idle open tab must not keep its session alive.
        return await _sessions.IsLiveAsync(user.FindFirstValue(HarpoClaims.SessionId), touch: false, cancellationToken);
    }
}

/// <summary>Per interactive page (circuit): whether the browser is connected right now.</summary>
public sealed class CircuitConnection : CircuitHandler
{
    public bool IsUp { get; private set; } = true;

    public override Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        IsUp = true;
        return Task.CompletedTask;
    }

    public override Task OnConnectionDownAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        IsUp = false;
        return Task.CompletedTask;
    }
}
