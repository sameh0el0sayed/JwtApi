using JwtApi.Helper;
using JwtApi.Models;
using JwtApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var JWTConfiguration = builder.Configuration.GetSection("JWT");

// Add services to the container.

services.Configure<JWTMaper>(JWTConfiguration);

services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>();

services.AddScoped<IAuthService, AuthService>();

services.AddDbContext<ApplicationDbContext>(options =>
options.UseSqlServer(connectionString)
);

services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
              .AddJwtBearer(o =>
              {
                  o.RequireHttpsMetadata = false;
                  o.SaveToken = false;
                  o.TokenValidationParameters = new TokenValidationParameters
                  {
                      ValidateIssuerSigningKey = true,
                      ValidateIssuer = true,
                      ValidateAudience = true,
                      ValidateLifetime = true,
                      ValidIssuer = builder.Configuration["JWT:Issuer"],
                      ValidAudience = builder.Configuration["JWT:Audience"],
                      IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
                  };
              });

services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
services.AddEndpointsApiExplorer();
services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
