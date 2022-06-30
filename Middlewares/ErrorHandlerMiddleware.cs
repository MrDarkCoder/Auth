using System.Net;
using System.Text.Json;
using Auth.Helper;

namespace Auth.Middlewares
{
    public class ErrorHandlerMiddleware
    {

        private readonly RequestDelegate _next;
        private readonly ILogger _logger;

        public ErrorHandlerMiddleware(RequestDelegate next, ILogger<ErrorHandlerMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext _httpContext)
        {
            try
            {
                await _next(_httpContext);
            }
            catch (Exception error)
            {
                var response = _httpContext.Response;
                response.ContentType = "application/json";

                switch (error)
                {
                    case AppException e:
                        response.StatusCode = (int)HttpStatusCode.BadRequest;
                        break;

                    case KeyNotFoundException e:
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                        break;
                    default:
                        // Unhandled Error in runtime
                        _logger.LogError(error, error.Message);
                        response.StatusCode = (int)HttpStatusCode.InternalServerError;
                        break;
                }

                var result = JsonSerializer.Serialize(new { message = error?.Message });

                await response.WriteAsync(result);
            }
        }


    }
}