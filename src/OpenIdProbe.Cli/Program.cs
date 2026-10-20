using Microsoft.Extensions.DependencyInjection;
using OpenIdProbe.Cli.Commands;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.Http;
using OpenIdProbe.Protocol.Jwks;

namespace OpenIdProbe.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        var command = args[0];
        var options = ParseOptions(args.Skip(1).ToArray());

        return command switch
        {
            "discover" => await RunDiscoverAsync(options),
            "jwks" => await RunJwksAsync(options),
            "validate-token" => await RunValidateTokenAsync(options),
            "auth-code" => await RunAuthCodeAsync(options),
            "userinfo" => await RunUserInfoAsync(options),
            "test" => await RunTestAsync(options),
            "version" => PrintVersion(),
            _ => PrintUnknownCommand(command)
        };
    }

    private static async Task<int> RunDiscoverAsync(Dictionary<string, string?> options)
    {
        if (!options.TryGetValue("issuer", out var issuer) || string.IsNullOrEmpty(issuer))
        {
            Console.Error.WriteLine("Error: --issuer is required");
            return 2;
        }

        var services = BuildServices(options);
        var verbose = options.ContainsKey("verbose");
        var format = options.GetValueOrDefault("format", "console")!;
        var outputPath = options.GetValueOrDefault("output");
        var output = outputPath != null ? new FileInfo(outputPath) : null;

        var handler = new DiscoverCommandHandler(services, verbose, format);
        return await handler.ExecuteAsync(issuer, output, CancellationToken.None);
    }

    private static async Task<int> RunJwksAsync(Dictionary<string, string?> options)
    {
        var issuer = options.GetValueOrDefault("issuer");
        var uri = options.GetValueOrDefault("uri");

        if (string.IsNullOrEmpty(issuer) && string.IsNullOrEmpty(uri))
        {
            Console.Error.WriteLine("Error: Either --issuer or --uri is required");
            return 2;
        }

        var services = BuildServices(options);
        var verbose = options.ContainsKey("verbose");
        var format = options.GetValueOrDefault("format", "console")!;
        var outputPath = options.GetValueOrDefault("output");
        var output = outputPath != null ? new FileInfo(outputPath) : null;

        var handler = new JwksCommandHandler(services, verbose, format);
        return await handler.ExecuteAsync(issuer, uri, output, CancellationToken.None);
    }

    private static async Task<int> RunTestAsync(Dictionary<string, string?> options)
    {
        if (!options.TryGetValue("issuer", out var issuer) || string.IsNullOrEmpty(issuer))
        {
            Console.Error.WriteLine("Error: --issuer is required");
            return 2;
        }

        var services = BuildServices(options);
        var verbose = options.ContainsKey("verbose");
        var format = options.GetValueOrDefault("format", "console")!;
        var suite = options.GetValueOrDefault("suite", "discovery")!;
        var outputPath = options.GetValueOrDefault("output");
        var output = outputPath != null ? new FileInfo(outputPath) : null;

        var handler = new TestCommandHandler(services, verbose, format);
        return await handler.ExecuteAsync(issuer, suite, output, CancellationToken.None);
    }

    private static async Task<int> RunValidateTokenAsync(Dictionary<string, string?> options)
    {
        if (!options.TryGetValue("issuer", out var issuer) || string.IsNullOrEmpty(issuer))
        {
            Console.Error.WriteLine("Error: --issuer is required");
            return 2;
        }

        if (!options.TryGetValue("audience", out var audience) || string.IsNullOrEmpty(audience))
        {
            Console.Error.WriteLine("Error: --audience is required");
            return 2;
        }

        if (!options.TryGetValue("token-file", out var tokenFile) || string.IsNullOrEmpty(tokenFile))
        {
            Console.Error.WriteLine("Error: --token-file is required");
            return 2;
        }

        var services = BuildServices(options);
        var verbose = options.ContainsKey("verbose");
        var format = options.GetValueOrDefault("format", "console")!;
        var nonce = options.GetValueOrDefault("nonce");
        var outputPath = options.GetValueOrDefault("output");
        var output = outputPath != null ? new FileInfo(outputPath) : null;

        var handler = new ValidateTokenCommandHandler(services, verbose, format);
        return await handler.ExecuteAsync(issuer, audience, tokenFile, nonce, output, CancellationToken.None);
    }

    private static async Task<int> RunAuthCodeAsync(Dictionary<string, string?> options)
    {
        if (!options.TryGetValue("issuer", out var issuer) || string.IsNullOrEmpty(issuer))
        {
            Console.Error.WriteLine("Error: --issuer is required");
            return 2;
        }

        if (!options.TryGetValue("client-id", out var clientId) || string.IsNullOrEmpty(clientId))
        {
            Console.Error.WriteLine("Error: --client-id is required");
            return 2;
        }

        var services = BuildServices(options);
        var verbose = options.ContainsKey("verbose");
        var format = options.GetValueOrDefault("format", "console")!;
        var redirectUri = options.GetValueOrDefault("redirect-uri", "http://127.0.0.1:8400/callback")!;
        var scopes = options.GetValueOrDefault("scopes", "openid profile email")!;
        var outputPath = options.GetValueOrDefault("output");
        var output = outputPath != null ? new FileInfo(outputPath) : null;

        var handler = new AuthCodeCommandHandler(services, verbose, format);
        return await handler.ExecuteAsync(issuer, clientId, redirectUri, scopes, output, CancellationToken.None);
    }

    private static async Task<int> RunUserInfoAsync(Dictionary<string, string?> options)
    {
        if (!options.TryGetValue("issuer", out var issuer) || string.IsNullOrEmpty(issuer))
        {
            Console.Error.WriteLine("Error: --issuer is required");
            return 2;
        }

        if (!options.TryGetValue("access-token", out var accessToken) || string.IsNullOrEmpty(accessToken))
        {
            Console.Error.WriteLine("Error: --access-token is required");
            return 2;
        }

        var services = BuildServices(options);
        var verbose = options.ContainsKey("verbose");
        var format = options.GetValueOrDefault("format", "console")!;
        var expectedSubject = options.GetValueOrDefault("expected-sub");
        var outputPath = options.GetValueOrDefault("output");
        var output = outputPath != null ? new FileInfo(outputPath) : null;

        var handler = new UserInfoCommandHandler(services, verbose, format);
        return await handler.ExecuteAsync(issuer, accessToken, expectedSubject, output, CancellationToken.None);
    }

    private static Dictionary<string, string?> ParseOptions(string[] args)
    {
        var options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg.StartsWith("--", StringComparison.Ordinal))
            {
                var key = arg[2..];
                string? value = null;

                // Check if next arg is a value (not a flag)
                if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                {
                    value = args[++i];
                }

                options[key] = value;
            }
            else if (arg.StartsWith('-'))
            {
                var key = arg switch
                {
                    "-i" => "issuer",
                    "-u" => "uri",
                    "-f" => "format",
                    "-o" => "output",
                    "-s" => "suite",
                    "-v" => "verbose",
                    _ => arg[1..]
                };

                string? value = null;

                if (key != "verbose" && i + 1 < args.Length && !args[i + 1].StartsWith('-'))
                {
                    value = args[++i];
                }

                options[key] = value;
            }
        }

        return options;
    }

    private static ServiceProvider BuildServices(Dictionary<string, string?> options)
    {
        var services = new ServiceCollection();

        var httpOptions = new ProbeHttpOptions
        {
            AllowInsecure = options.ContainsKey("allow-insecure"),
            AllowPrivateNetwork = options.ContainsKey("allow-private-network")
        };

        services.AddSingleton(httpOptions);
        services.AddSingleton<IUrlSafetyValidator, UrlSafetyValidator>();
        services.AddSingleton<IDiscoveryValidator, DiscoveryValidator>();
        services.AddSingleton<IJwksValidator, JwksValidator>();

        services.AddHttpClient<IDiscoveryClient, DiscoveryClient>()
            .ConfigureHttpClient(client =>
            {
                client.Timeout = httpOptions.Timeout;
                client.DefaultRequestHeaders.UserAgent.ParseAdd(httpOptions.UserAgent);
            });

        services.AddHttpClient<IJwksClient, JwksClient>()
            .ConfigureHttpClient(client =>
            {
                client.Timeout = httpOptions.Timeout;
                client.DefaultRequestHeaders.UserAgent.ParseAdd(httpOptions.UserAgent);
            });

        return services.BuildServiceProvider();
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            OpenID Probe - OIDC interoperability testing toolkit

            USAGE:
                openid-probe <command> [options]

            COMMANDS:
                discover        Fetch and validate an OIDC discovery document
                jwks            Fetch and validate a JWKS document
                validate-token  Validate an ID token
                auth-code       Run interactive authorization code flow with PKCE
                userinfo        Fetch and validate UserInfo endpoint response
                test            Run a test suite against an OIDC provider
                version         Show version information
                help            Show this help

            GLOBAL OPTIONS:
                -v, --verbose              Show detailed output
                -f, --format <format>      Output format (console, json) [default: console]
                -o, --output <file>        Write output to file
                --allow-insecure           Allow HTTP (non-HTTPS) connections
                --allow-private-network    Allow connections to private network addresses

            DISCOVER OPTIONS:
                -i, --issuer <url>         The issuer URL (required)

            JWKS OPTIONS:
                -i, --issuer <url>         The issuer URL (fetches discovery first)
                -u, --uri <url>            The JWKS URI directly

            VALIDATE-TOKEN OPTIONS:
                -i, --issuer <url>         The issuer URL (required)
                --audience <client-id>     Expected audience (required)
                --token-file <path>        Path to file containing the ID token (required)
                --nonce <nonce>            Expected nonce value

            AUTH-CODE OPTIONS:
                -i, --issuer <url>         The issuer URL (required)
                --client-id <id>           OAuth client ID (required)
                --redirect-uri <uri>       Redirect URI [default: http://127.0.0.1:8400/callback]
                --scopes <scopes>          Space-separated scopes [default: openid profile email]

            USERINFO OPTIONS:
                -i, --issuer <url>         The issuer URL (required)
                --access-token <token>     Access token for authentication (required)
                --expected-sub <sub>       Expected subject claim to validate

            TEST OPTIONS:
                -i, --issuer <url>         The issuer URL (required)
                -s, --suite <suite>        Test suite (discovery, jwks, all) [default: discovery]

            EXAMPLES:
                openid-probe discover --issuer https://accounts.google.com
                openid-probe jwks --issuer https://accounts.google.com
                openid-probe validate-token -i https://example.com --audience my-app --token-file ./token.txt
                openid-probe auth-code -i https://example.com --client-id my-app
                openid-probe userinfo -i https://example.com --access-token eyJhbGciOiJSUzI1NiIsInR...
                openid-probe test --issuer https://accounts.google.com --suite all

            EXIT CODES:
                0    Success (all tests passed)
                1    Failure (one or more tests failed)
                2    Error (invalid arguments or runtime error)
            """);
    }

    private static int PrintVersion()
    {
        Console.WriteLine("OpenID Probe 1.0.0");
        return 0;
    }

    private static int PrintUnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        Console.Error.WriteLine("Run 'openid-probe help' for usage information.");
        return 2;
    }
}
