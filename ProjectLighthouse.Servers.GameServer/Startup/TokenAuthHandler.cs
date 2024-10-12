using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using LBPUnion.ProjectLighthouse.Database;
using LBPUnion.ProjectLighthouse.Helpers;
using LBPUnion.ProjectLighthouse.Types.Entities.Token;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;


using System.Text;
using LBPUnion.ProjectLighthouse.Configuration;
using LBPUnion.ProjectLighthouse.Database;
using LBPUnion.ProjectLighthouse.Extensions;
using LBPUnion.ProjectLighthouse.Helpers;
using LBPUnion.ProjectLighthouse.Localization;
using LBPUnion.ProjectLighthouse.Localization.StringLists;
using LBPUnion.ProjectLighthouse.Logging;
using LBPUnion.ProjectLighthouse.Serialization;
using LBPUnion.ProjectLighthouse.Types.Entities.Notifications;
using LBPUnion.ProjectLighthouse.Types.Entities.Profile;
using LBPUnion.ProjectLighthouse.Types.Entities.Token;
using LBPUnion.ProjectLighthouse.Types.Logging;
using LBPUnion.ProjectLighthouse.Types.Mail;
using LBPUnion.ProjectLighthouse.Types.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;





namespace LBPUnion.ProjectLighthouse.Servers.GameServer.Startup;

public class TokenAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly DatabaseContext database;
    private const string cookie = "MM_AUTH";

    public TokenAuthHandler
    (
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        UrlEncoder encoder,
        DatabaseContext database
    ) : base(options, new NullLoggerFactory(), encoder)
    {
        this.database = database;
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        this.Context.Response.StatusCode = 403;
        return Task.CompletedTask;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
                                if (context.Request.Path.ToString().StartsWith("/LITTLEBIGPLANETPS3_XML/announce")) {
            Logger.Warn("got to annocoment broo so something done messed up after me", LogArea.Login);
            }
        if (!this.Context.Request.Cookies.ContainsKey(cookie)) return AuthenticateResult.Fail("No auth cookie");

        GameTokenEntity? gameToken = await this.database.GameTokenFromRequest(this.Request);
        if (gameToken == null) return AuthenticateResult.Fail("No game token");

        IPAddress? remoteIpAddress = this.Context.Connection.RemoteIpAddress;
        if (remoteIpAddress == null) return AuthenticateResult.Fail("Failed to determine IP address");

        if (CryptoHelper.Sha256Hash(remoteIpAddress.ToString()) != gameToken.LocationHash)
            return AuthenticateResult.Fail("IP address change detected");

        this.Context.Items["Token"] = gameToken;
        Claim[] claims =
        [
            new Claim("userId", gameToken.UserId.ToString()),
        ];
        ClaimsIdentity identity = new(claims, this.Scheme.Name);
        ClaimsPrincipal principal = new(identity);
        AuthenticationTicket ticket = new(principal, this.Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}
