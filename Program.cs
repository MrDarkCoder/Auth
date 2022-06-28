
using System.Text.Json.Serialization;
using Auth.Data;
using Auth.Helper;

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

    //! TODO : Auto Mapper

    // Configure strongly typed setting objects
    builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

    //! TODO : Add Services/Repositories into DI

    // Swagger UI
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
}

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

