using JWTExampleApi.Models;
using JWTExampleApi.Records;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

#region JWTRegion
//JWT
var jwtOptions = builder.Configuration
    .GetSection("JwtOptions")
    .Get<JwtOptions>();

builder.Services.AddSingleton(jwtOptions);

// 👇 Configuring the Authentication Service
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>
    {
        //convert the string signing key to byte array
        byte[] signingKeyBytes = Encoding.UTF8
            .GetBytes(jwtOptions.SigningKey);

        opts.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidAudience = jwtOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes)
        };
    });

// 👇 Configuring the Authorization Service
builder.Services.AddAuthorization();
#endregion

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!");
app.MapGet("/public", () => "Public Hello World!").AllowAnonymous();
app.MapGet("/private", () => "Private Hello World!").RequireAuthorization();

app.MapPost("/tokens/connect", (HttpContext ctx, JwtOptions jwtOptions)
    => TokenEndpoint.Connect(ctx, jwtOptions));

//read the jwt token from header
app.MapGet("/jwt-token/headers", (HttpContext ctx) =>
{
    if (ctx.Request.Headers.TryGetValue("Authorization", out var headerAuth))
    {
        var jwtToken = headerAuth.First().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[1];
        return Task.FromResult(TypedResults.Ok(new { token = jwtToken }));
    }
    return Task.FromResult(TypedResults.NotFound(new { message = "jwt not found" }));
});

//read the jwt token from authentication context
app.MapGet("/jwt-token/context", async (HttpContext ctx) =>
{
    var token = await ctx.GetTokenAsync("access_token");

    return TypedResults.Ok(new { token = token });
});

app.Run();

app.MapControllers();

app.Run();
