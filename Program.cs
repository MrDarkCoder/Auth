
using System.Text.Json.Serialization;
using Auth.Data;
using Auth.Helper;
using Auth.Middlewares;
using Auth.Repository.Interfaces;
using Auth.Repository.Services;
using Swashbuckle.AspNetCore.Filters;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
{
    // Adding DbContext
    builder.Services.AddDbContext<AuthContext>();

    //! TODO : Add Cors

    // Controllers + Json Serializing For ENUM as STRING
    builder.Services.AddControllers()
                    .AddJsonOptions(
                        x => x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter())
                    );

    // Auto Mapper : Injected
    builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    // Configure strongly typed setting objects
    builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

    // Add Services/Repositories into DI
    builder.Services.AddScoped<IJwtUtillRepository, JwtUtillService>();
    builder.Services.AddScoped<IAuthRepository, AuthService>();
    builder.Services.AddScoped<IEmailRepository, EmailService>();
    builder.Services.AddScoped<IAccountRepository, AccountService>();

    // Swagger UI
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(
        options =>
        {
            options.AddSecurityDefinition("oauth2", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Description = "Bearer {token}",
                In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                Name = "Authorization",
                Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
                Scheme = "Bearer"
            });
            options.OperationFilter<SecurityRequirementsOperationFilter>();
        }
    );
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<ErrorHandlerMiddleware>();

app.UseHttpsRedirection();

// app.UseAuthorization();
app.UseHttpLogging();


// using custom middle ware for authenticate and authorize
app.UseMiddleware<AuthMiddleware>();


app.MapControllers();

app.Run();




// console.log(require('crypto').randomBytes(256).toString('base64'));