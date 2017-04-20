using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            // Set up configuration sources.
            Configuration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("config.user.json")
                .AddJsonFile("appsettings.json")
                .Build();
        }

        public IConfigurationRoot Configuration { get; set; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddAuthentication(sharedOptions => sharedOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);

            services.AddTransient<IClaimsTransformer, MyClaimsTransformer>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            // Add the console logger.
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));

            // Configure error handling middleware.
            app.UseExceptionHandler("/Home/Error");

            // Add static files to the request pipeline.
            app.UseStaticFiles();

            app.UseAzureAuth(Configuration);

            // Configure MVC routes
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        // Handle sign-in errors differently than generic errors.
        private Task OnAuthenticationFailed(FailureContext context)
        {
            context.HandleResponse();
            context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
            return Task.CompletedTask;
        }
    }

    public static class ApplicationExtensions
    {
        public static void UseAzureAuth(this IApplicationBuilder app, IConfiguration configuration)
        {
            var transformer = app.ApplicationServices.GetService<IClaimsTransformer>();
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                Events = new CookieAuthenticationEvents
                {
                }
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions
            {
                ClientId = configuration["AzureAD:ClientId"],
                Authority = string.Format(configuration["AzureAd:AadInstance"], configuration["AzureAd:Tenant"]),
                ResponseType = OpenIdConnectResponseType.IdToken,
                PostLogoutRedirectUri = configuration["AzureAd:PostLogoutRedirectUri"],
                Events = new OpenIdConnectEvents
                {
                    OnTicketReceived = new Coordinator(transformer).OnTicketReceived,
                    OnTokenValidated = c =>
                    {
                        return Task.CompletedTask;
                    },
                    OnTokenResponseReceived = c =>
                    {
                        return Task.CompletedTask;
                    },
                    OnRemoteFailure = (context) =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
                        return Task.CompletedTask;
                    },
                }
            });
        }
    }

    public class Coordinator
    {
        private readonly IClaimsTransformer _transformer;

        public Coordinator(IClaimsTransformer transformer)
        {
            _transformer = transformer;
        }

        public async Task OnTicketReceived(TicketReceivedContext context)
        {
            var result = await _transformer.Transform(context.Principal);
            context.Principal = result;

            // may want to also replace the ticket
        }
    }

    public interface IClaimsTransformer
    {
        Task<ClaimsPrincipal> Transform(ClaimsPrincipal principal);
    }

    public class MyClaimsTransformer : IClaimsTransformer
    {
        public Task<ClaimsPrincipal> Transform(ClaimsPrincipal principal)
        {
            // return Task.FromResult(principal);

            var identity = (ClaimsIdentity)principal.Identity;

            var name = identity.FindFirst(ClaimTypes.Name);
            var aud = identity.FindFirst("aud");
            var iss = identity.FindFirst("iss");
            var iat = identity.FindFirst("iat");

            var claimsToKeep = new List<Claim> {name, aud, iat, iss};

            var newIdentity = new ClaimsIdentity(claimsToKeep, identity.AuthenticationType);

            return Task.FromResult(new ClaimsPrincipal(newIdentity));
        }
    }
}
