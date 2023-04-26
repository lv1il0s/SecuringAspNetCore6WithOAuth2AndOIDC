using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews()
    .AddJsonOptions(configure => 
        configure.JsonSerializerOptions.PropertyNamingPolicy = null);

// create an HttpClient used for accessing the API
builder.Services.AddHttpClient("APIClient", client =>
{
    client.BaseAddress = new Uri(builder.Configuration["ImageGalleryAPIRoot"]);
    client.DefaultRequestHeaders.Clear();
    client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
});

// Taking care of the client-side part of the OIDC flow. We also need somewhere to store user's identity.

// We configure authentication middleware with this call.
builder.Services.AddAuthentication(options =>
{
    // Constant value - we can also choose this value, but it should correspond to the logical name for a particular authentication scheme.
    // In our case, we are fine with "Cookies". By setting this value, we can sign into this scheme, we can sign out of it, and we can read
    // scheme-related information, and so on, simply by referring to this cookies scheme name. This is not strictly necessary in our case, but
    // it's good to be explicit about it so we can get a better understanding of what's going on. 
    // Moreover, if we are hosting different applications on the same server, we'll want to ensure that these have a different scheme name
    // in order to avoid them interfering with each other.
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    // This value will have to match the scheme we use to configure the OIDC (below). 
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
// This configures the cookie handler, and it enables our app to use cookie-based authentication or our default scheme. What this means is 
// that once the identity token is validated and transformed into a claims identity, it will be stored in an encrypted cookie, and that 
// cookie is then used on subsequent requests to the web app to check whether or not we are making an authenticated request. In other words,
// it's the cookie that is checked by our web app because we configured it like this.
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
// Then, we register and connect OIDC handler via this call - this enables our app to support the OIDC authentication workflow. In our case,
// that will be the code flow. In other words, it is this handler that will handle creating authorization requests, token requests, and other
// requests, and it will ensure that identity token validation happens.
// We register these services for the OIDC scheme - this will ensure that when a part of our app requires authentication, OIDC will be triggered
// as default, as we set the DefaultChallengeScheme to OIDC as well. 
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Sign-in scheme is set to cookies - that matches the default scheme name for authentication. This ensures that the successful result of
    // authentication will be stored in the cookie matching this scheme. 
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

    // Authority should be set to the address of our IDP, because that is the authority responsible for the IDP part of the OIDC flows. 
    // The middleware will use this value to read the metadata on the discovery endpoint so it knows where to find the different endpoints 
    // and other information.
    options.Authority = "https://localhost:5001";

    // ClientId should match the the ClientId at the level of the IDP.
    options.ClientId = "imagegalleryclient";

    // Secret should match the secret at the level of the IDP.
    // This ensures that our client can do an authenticated call to the token endpoint.
    options.ClientSecret = "secret";

    // ResponseType corresponds to a grant or flow - by setting it to code, we signify that we want to use the code grant. For that one,
    // PKCE protection is required, and the middleware automatically enables this when code is the ResponseType.
    options.ResponseType = "code";
    // We set the scopes that we want our app to request. We don't have to do this explicitly though. By default, openid and profile scopes
    // are requested by the middleware, so we can comment it out.
    //options.Scope.Add("openid");
    //options.Scope.Add("profile");

    // We set the redirect URI to our host followed by the /signin-oidc at the level of the IDP for this client. We also need to configure
    // it here at the client side as it's part of the validation process of the request.
    // But, /signin-oidcs is the default value used by this middleware, so we can comment it out as well.
    //options.CallbackPath = new PathString("signin-oidc");

    // This allows the middleware to save the tokens it receives from the IDP so that they can be used afterwards.
    options.SaveTokens = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Gallery}/{action=Index}/{id?}");

app.Run();
