using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Soenneker.Extensions.Configuration;
using Soenneker.Hashing.Pbkdf2;
using Soenneker.Validators.BasicAuth.Abstract;
using System;
using Soenneker.Security.Util;
using Soenneker.Security.Parsers.BasicAuth;
using Microsoft.AspNetCore.Http;

namespace Soenneker.Validators.BasicAuth;

/// <inheritdoc cref="IBasicAuthValidator" />
public sealed class BasicAuthValidator : Validator.Validator, IBasicAuthValidator
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<BasicAuthValidator> _logger;

    public BasicAuthValidator(IConfiguration configuration, ILogger<BasicAuthValidator> logger) : base(logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public bool Validate(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null)
    {
        configuredUsername ??= _configuration.GetStringStrict("BasicAuth:Username");
        configuredPasswordPhc ??= _configuration.GetStringStrict("BasicAuth:PasswordPhc");

        char[]? charBuffer = null;

        try
        {
            bool parsed = BasicAuthParser.TryReadBasicCredentials(httpContext, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password,
                out charBuffer);

            if (!parsed)
            {
                _logger.LogWarning("Could not parse basic credentials");
                throw new UnauthorizedAccessException("Invalid credentials");
            }

            // Always verify the password so username mismatches do not skip the expensive hash.
            bool usernameValid = SecurityUtil.FixedCostEqualsUtf8(username, configuredUsername);
            bool passwordValid = Pbkdf2HashingUtil.Verify(password, configuredPasswordPhc);

            if (!usernameValid || !passwordValid)
            {
                _logger.LogWarning("Invalid Basic Auth credentials provided");
                throw new UnauthorizedAccessException("Invalid credentials");
            }

            return true;
        }
        finally
        {
            BasicAuthParser.Clear(charBuffer);
        }
    }

    public bool ValidateSafe(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null)
    {
        configuredUsername ??= _configuration.GetStringStrict("BasicAuth:Username");
        configuredPasswordPhc ??= _configuration.GetStringStrict("BasicAuth:PasswordPhc");

        char[]? charBuffer = null;

        try
        {
            bool parsed = BasicAuthParser.TryReadBasicCredentials(httpContext, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password,
                out charBuffer);

            if (!parsed)
            {
                _logger.LogWarning("Could not parse basic credentials");
                return false;
            }

            // Always verify the password so username mismatches do not skip the expensive hash.
            bool usernameValid = SecurityUtil.FixedCostEqualsUtf8(username, configuredUsername);
            bool passwordValid = Pbkdf2HashingUtil.Verify(password, configuredPasswordPhc);

            if (!usernameValid || !passwordValid)
            {
                _logger.LogWarning("Invalid Basic Auth credentials provided");
                return false;
            }

            return true;
        }
        finally
        {
            BasicAuthParser.Clear(charBuffer);
        }
    }
}
