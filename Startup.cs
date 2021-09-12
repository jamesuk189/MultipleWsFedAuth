using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MultipleWsFedAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services
                .AddAuthentication(sharedOptions =>
                {
                    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddWsFederation("OrgA", options =>
                {
                    options.Wtrealm = Configuration["OrgA:WsFed:Realm"];
                    options.MetadataAddress = Configuration["OrgA:WsFed:Metadata"];
                    options.CallbackPath = "/signin-wsfed-orga";
                    options.Events.OnTicketReceived = (context) => HandleOnTicketReceivedAsync(context, "OrgA");
                })
                .AddWsFederation("OrgB", options =>
                {
                    options.Wtrealm = Configuration["OrgB:WsFed:Realm"];
                    options.MetadataAddress = Configuration["OrgB:WsFed:Metadata"];
                    options.CallbackPath = "/signin-wsfed-orgb";
                    options.Events.OnTicketReceived = (context) => HandleOnTicketReceivedAsync(context, "OrgB");
                })
                .AddCookie(options =>
                {
                    options.LoginPath = new PathString("/Account/SignIn");
                });

            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }

        private Task HandleOnTicketReceivedAsync(TicketReceivedContext context, string scheme)
        {
            ClaimsIdentity claimsIdentity = context.Principal.Identity as ClaimsIdentity;

            if (claimsIdentity is null)
            {
                return Task.CompletedTask;
            }

            claimsIdentity.AddClaim(new Claim("local:authscheme", scheme));

            return Task.CompletedTask;
        }
    }
}
