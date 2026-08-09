using System.Net.Http;

namespace HashGuardScanner;

/// <summary>
/// Shared HTTP handler so scans do not allocate a new connection pool per request.
/// Callers create short-lived <see cref="HttpClient"/> wrappers with their own timeout
/// and headers; disposing those clients does not dispose the shared handler.
/// </summary>
internal static class AppHttp
{
    private static readonly SocketsHttpHandler SharedHandler = new()
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        MaxConnectionsPerServer = 8,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    };

    /// <summary>
    /// Creates an <see cref="HttpClient"/> that reuses the process-wide handler.
    /// Safe to dispose after each scan/request batch.
    /// </summary>
    public static HttpClient Create(TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero)
        {
            timeout = TimeSpan.FromSeconds(30);
        }

        return new HttpClient(SharedHandler, disposeHandler: false)
        {
            Timeout = timeout,
        };
    }

    public static HttpClient Create(int timeoutSeconds) =>
        Create(TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 1, 600)));
}
