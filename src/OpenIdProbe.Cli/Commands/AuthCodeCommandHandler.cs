using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIdProbe.Core;
using OpenIdProbe.Protocol.Discovery;
using OpenIdProbe.Protocol.Jwks;
using OpenIdProbe.Protocol.OAuth;
using OpenIdProbe.Protocol.Tokens;
using OpenIdProbe.Reporting;

namespace OpenIdProbe.Cli.Commands;

public sealed class AuthCodeCommandHandler
{
    private readonly IServiceProvider _services;
    private readonly bool _verbose;
    private readonly string _format;

    public AuthCodeCommandHandler(IServiceProvider services, bool verbose, string format)
    {
        _services = services;
        _verbose = verbose;
        _format = format;
    }

    public async Task<int> ExecuteAsync(
        string issuer,
        string clientId,
        string redirectUri,
        string scopes,
        FileInfo? outputFile,
        CancellationToken cancellationToken)
    {
        var results = new List<TestResult>();
        var stopwatch = Stopwatch.StartNew();

        Console.WriteLine("Starting Authorization Code flow with PKCE...");
        Console.WriteLine($"Issuer: {issuer}");
        Console.WriteLine($"Client ID: {clientId}");
        Console.WriteLine($"Redirect URI: {redirectUri}");
        Console.WriteLine($"Scopes: {scopes}");
        Console.WriteLine();

        // Step 1: Fetch discovery document
        Console.WriteLine("Fetching discovery document...");
        var discoveryClient = _services.GetRequiredService<IDiscoveryClient>();
        var discoveryResult = await discoveryClient.GetDiscoveryDocumentAsync(issuer, cancellationToken);

        if (!discoveryResult.IsSuccess)
        {
            Console.Error.WriteLine($"Error: Failed to fetch discovery document: {discoveryResult.Error}");
            results.Add(new TestResult(
                "AUTHCODE-001",
                "Fetch discovery document",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: discoveryResult.Error));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        var discovery = discoveryResult.Document!;
        results.Add(new TestResult(
            "AUTHCODE-001",
            "Fetch discovery document",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        // Check required endpoints
        if (string.IsNullOrEmpty(discovery.AuthorizationEndpoint))
        {
            Console.Error.WriteLine("Error: Discovery document missing authorization_endpoint");
            results.Add(new TestResult(
                "AUTHCODE-002",
                "Discovery has authorization_endpoint",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "authorization_endpoint is required for authorization code flow"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        if (string.IsNullOrEmpty(discovery.TokenEndpoint))
        {
            Console.Error.WriteLine("Error: Discovery document missing token_endpoint");
            results.Add(new TestResult(
                "AUTHCODE-003",
                "Discovery has token_endpoint",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "token_endpoint is required for authorization code flow"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        results.Add(new TestResult(
            "AUTHCODE-002",
            "Discovery has authorization_endpoint",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        results.Add(new TestResult(
            "AUTHCODE-003",
            "Discovery has token_endpoint",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        // Step 2: Generate PKCE values
        Console.WriteLine("Generating PKCE parameters...");
        var codeVerifier = Pkce.GenerateCodeVerifier();
        var codeChallenge = Pkce.ComputeCodeChallenge(codeVerifier);
        var state = Pkce.GenerateState();
        var nonce = Pkce.GenerateNonce();

        if (_verbose)
        {
            Console.WriteLine($"  Code verifier: {codeVerifier[..10]}...");
            Console.WriteLine($"  Code challenge: {codeChallenge}");
            Console.WriteLine($"  State: {state}");
            Console.WriteLine($"  Nonce: {nonce}");
        }

        results.Add(new TestResult(
            "AUTHCODE-010",
            "Generate PKCE code verifier and challenge",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        // Step 3: Build authorization URL
        var authUrl = new AuthorizationUrlBuilder(discovery.AuthorizationEndpoint)
            .WithClientId(clientId)
            .WithRedirectUri(redirectUri)
            .WithCodeChallenge(codeChallenge)
            .WithState(state)
            .WithNonce(nonce)
            .WithScopes(scopes)
            .Build();

        Console.WriteLine($"Authorization URL: {authUrl}");
        Console.WriteLine();

        results.Add(new TestResult(
            "AUTHCODE-011",
            "Build authorization URL with PKCE",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        // Step 4: Start loopback server
        Console.WriteLine("Starting callback server...");
        await using var callbackServer = new LoopbackCallbackServer(redirectUri);
        await callbackServer.StartAsync();

        results.Add(new TestResult(
            "AUTHCODE-012",
            "Start loopback callback server",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        // Step 5: Open browser
        Console.WriteLine("Opening browser for authentication...");
        Console.WriteLine("(Complete authentication in your browser)");
        Console.WriteLine();

        if (!TryOpenBrowser(authUrl))
        {
            Console.WriteLine("Could not open browser automatically.");
            Console.WriteLine($"Please navigate to: {authUrl}");
        }

        // Step 6: Wait for callback
        Console.WriteLine("Waiting for callback...");
        using var callbackTimeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, callbackTimeout.Token);

        CallbackResult callbackResult;
        try
        {
            callbackResult = await callbackServer.WaitForCallbackAsync(linkedCts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Error: Callback timed out after 5 minutes");
            results.Add(new TestResult(
                "AUTHCODE-020",
                "Receive authorization callback",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "Callback timed out"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        // Validate callback
        if (callbackResult.Error != null)
        {
            Console.Error.WriteLine($"Error: Authorization failed: {callbackResult.Error}");
            if (callbackResult.ErrorDescription != null)
            {
                Console.Error.WriteLine($"  Description: {callbackResult.ErrorDescription}");
            }
            results.Add(new TestResult(
                "AUTHCODE-020",
                "Receive authorization callback",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: $"{callbackResult.Error}: {callbackResult.ErrorDescription}"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        if (callbackResult.Code == null)
        {
            Console.Error.WriteLine("Error: No authorization code received");
            results.Add(new TestResult(
                "AUTHCODE-020",
                "Receive authorization callback",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "No authorization code in callback"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        Console.WriteLine("Received authorization code!");
        results.Add(new TestResult(
            "AUTHCODE-020",
            "Receive authorization callback",
            TestOutcome.Pass,
            stopwatch.Elapsed));

        // Validate state
        if (callbackResult.State != state)
        {
            Console.Error.WriteLine($"Error: State mismatch (expected: {state}, got: {callbackResult.State})");
            results.Add(new TestResult(
                "AUTHCODE-021",
                "State parameter matches",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "State parameter mismatch - possible CSRF attack",
                SpecReference: "RFC 6749 Section 10.12"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        results.Add(new TestResult(
            "AUTHCODE-021",
            "State parameter matches",
            TestOutcome.Pass,
            stopwatch.Elapsed,
            SpecReference: "RFC 6749 Section 10.12"));

        // Step 7: Exchange code for tokens
        Console.WriteLine("Exchanging authorization code for tokens...");
        var tokenClient = new TokenClient(new HttpClient());
        var tokenRequest = new TokenExchangeRequest
        {
            TokenEndpoint = discovery.TokenEndpoint,
            Code = callbackResult.Code,
            CodeVerifier = codeVerifier,
            ClientId = clientId,
            RedirectUri = redirectUri
        };

        var tokenResponse = await tokenClient.ExchangeCodeAsync(tokenRequest, cancellationToken);

        if (!tokenResponse.IsSuccess)
        {
            Console.Error.WriteLine($"Error: Token exchange failed: {tokenResponse.Error}");
            if (tokenResponse.ErrorDescription != null)
            {
                Console.Error.WriteLine($"  Description: {tokenResponse.ErrorDescription}");
            }
            results.Add(new TestResult(
                "AUTHCODE-030",
                "Exchange authorization code for tokens",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: $"{tokenResponse.Error}: {tokenResponse.ErrorDescription}"));
            return OutputResults(results, issuer, outputFile, cancellationToken);
        }

        Console.WriteLine("Token exchange successful!");
        results.Add(new TestResult(
            "AUTHCODE-030",
            "Exchange authorization code for tokens",
            TestOutcome.Pass,
            stopwatch.Elapsed,
            SpecReference: "RFC 7636 Section 4.5"));

        // Check access token
        if (string.IsNullOrEmpty(tokenResponse.AccessToken))
        {
            results.Add(new TestResult(
                "AUTHCODE-031",
                "Token response contains access_token",
                TestOutcome.Fail,
                stopwatch.Elapsed,
                FailureReason: "No access_token in token response"));
        }
        else
        {
            results.Add(new TestResult(
                "AUTHCODE-031",
                "Token response contains access_token",
                TestOutcome.Pass,
                stopwatch.Elapsed));
        }

        // Check ID token
        if (string.IsNullOrEmpty(tokenResponse.IdToken))
        {
            results.Add(new TestResult(
                "AUTHCODE-032",
                "Token response contains id_token",
                TestOutcome.Warn,
                stopwatch.Elapsed,
                FailureReason: "No id_token in token response (optional depending on scopes)"));
        }
        else
        {
            results.Add(new TestResult(
                "AUTHCODE-032",
                "Token response contains id_token",
                TestOutcome.Pass,
                stopwatch.Elapsed));

            // Step 8: Validate ID token
            Console.WriteLine("Validating ID token...");

            // Fetch JWKS
            if (string.IsNullOrEmpty(discovery.JwksUri))
            {
                results.Add(new TestResult(
                    "AUTHCODE-040",
                    "Validate ID token signature",
                    TestOutcome.Skip,
                    stopwatch.Elapsed,
                    FailureReason: "No jwks_uri in discovery document"));
            }
            else
            {
                var jwksClient = _services.GetRequiredService<IJwksClient>();
                var jwksResult = await jwksClient.GetJwksAsync(discovery.JwksUri, cancellationToken);

                if (!jwksResult.IsSuccess)
                {
                    results.Add(new TestResult(
                        "AUTHCODE-040",
                        "Validate ID token signature",
                        TestOutcome.Fail,
                        stopwatch.Elapsed,
                        FailureReason: $"Failed to fetch JWKS: {jwksResult.Error}"));
                }
                else
                {
                    var signingKeys = jwksResult.Jwks!.Keys
                        .Where(k => k.IsSigningKey)
                        .Select(ConvertToMsftJwk)
                        .ToList();

                    var validator = new IdTokenValidator();
                    var validationOptions = new IdTokenValidationOptions
                    {
                        Issuer = issuer,
                        Audience = clientId,
                        Nonce = nonce,
                        SigningKeys = signingKeys
                    };

                    var validationResults = validator.Validate(tokenResponse.IdToken, validationOptions);
                    results.AddRange(validationResults.Select(r => r with { TestId = $"AUTHCODE-{r.TestId}" }));

                    Console.WriteLine($"ID token validation: {validationResults.Count(r => r.Outcome == TestOutcome.Pass)} passed, {validationResults.Count(r => r.Outcome == TestOutcome.Fail)} failed");
                }
            }
        }

        if (_verbose && tokenResponse.ExpiresIn.HasValue)
        {
            Console.WriteLine($"Access token expires in: {tokenResponse.ExpiresIn} seconds");
        }

        Console.WriteLine();
        return OutputResults(results, issuer, outputFile, cancellationToken);
    }

    private int OutputResults(List<TestResult> results, string issuer, FileInfo? outputFile, CancellationToken cancellationToken)
    {
        var testRun = new TestRunResult(issuer, "auth-code", results);

        var formatter = GetFormatter();
        var output = formatter.FormatReport(testRun);

        if (outputFile != null)
        {
            File.WriteAllText(outputFile.FullName, output);
            Console.WriteLine($"Report written to: {outputFile.FullName}");
        }
        else
        {
            Console.Write(output);
        }

        return testRun.HasFailures ? 1 : 0;
    }

    private static Microsoft.IdentityModel.Tokens.JsonWebKey ConvertToMsftJwk(Protocol.Jwks.JsonWebKey jwk)
    {
        var msftJwk = new Microsoft.IdentityModel.Tokens.JsonWebKey
        {
            Kty = jwk.KeyType,
            Kid = jwk.KeyId,
            Use = jwk.Use,
            Alg = jwk.Algorithm
        };

        if (jwk.IsRsa)
        {
            msftJwk.N = jwk.Modulus;
            msftJwk.E = jwk.Exponent;
        }
        else if (jwk.IsEc)
        {
            msftJwk.Crv = jwk.Curve;
            msftJwk.X = jwk.X;
            msftJwk.Y = jwk.Y;
        }

        return msftJwk;
    }

    private static bool TryOpenBrowser(string url)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Process.Start(new ProcessStartInfo("cmd", $"/c start {url.Replace("&", "^&")}") { CreateNoWindow = true });
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start("xdg-open", url);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Process.Start("open", url);
            }
            else
            {
                return false;
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private IReportFormatter GetFormatter() => _format.ToLowerInvariant() switch
    {
        "json" => new JsonReportFormatter(),
        _ => new ConsoleReportFormatter(_verbose)
    };
}
