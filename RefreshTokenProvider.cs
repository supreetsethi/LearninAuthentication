using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

public class RefreshTokenProvider : IAuthenticationTokenProvider
{
    private static ConcurrentDictionary<string, AuthenticationTicket> _refreshToken = new ConcurrentDictionary<string, AuthenticationTicket>();
    public void Create(AuthenticationTokenCreateContext context)
    {
        var guid = Guid.NewGuid().ToString();

        var refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary)
        {
            IssuedUtc = context.Ticket.Properties.IssuedUtc,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(60)
        };
        var refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);

        _refreshToken.TryAdd(guid, refreshTokenTicket);
        context.SetToken(guid);
    }

    public async Task CreateAsync(AuthenticationTokenCreateContext context)
    {
        var guid = Guid.NewGuid().ToString();

        var refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary)
        {
            IssuedUtc = context.Ticket.Properties.IssuedUtc,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(60)
        };
        var refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);

        _refreshToken.TryAdd(guid, refreshTokenTicket);
        context.SetToken(guid);
    }

    public void Receive(AuthenticationTokenReceiveContext context)
    {
        //AuthenticationTicket ticket;
        //string header = context.OwinContext.Request.Headers["Authorization"];

        //if (_refreshToken.TryRemove(context.Token, out ticket))
        //{
        //    context.SetTicket(ticket);
        //}
         new NotImplementedException();
    }

    public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
    {
       
        AuthenticationTicket ticket;
        string header = context.OwinContext.Request.Headers["Authorization"];

        if (_refreshToken.TryRemove(context.Token, out ticket))
        {
            context.SetTicket(ticket);
        }

    }
}