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

///<inheritdoc cref="IBasicAuthValidator"/>
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
        configuredUsername ??= _configuration.GetValueStrict<string>("BasicAuth:Username");
        configuredPasswordPhc ??= _configuration.GetValueStrict<string>("BasicAuth:PasswordPhc");

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

            if (!SecurityUtil.FixedCostEqualsUtf8(username, configuredUsername))
            {
                _logger.LogWarning("Invalid Basic Auth username provided");
                throw new UnauthorizedAccessException("Invalid credentials");
            }

            if (!Pbkdf2HashingUtil.Verify(password, configuredPasswordPhc))
            {
                _logger.LogWarning("Invalid Basic Auth password provided");
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
        configuredUsername ??= _configuration.GetValueStrict<string>("BasicAuth:Username");
        configuredPasswordPhc ??= _configuration.GetValueStrict<string>("BasicAuth:PasswordPhc");

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

            if (!SecurityUtil.FixedCostEqualsUtf8(username, configuredUsername))
            {
                _logger.LogWarning("Invalid Basic Auth username provided");
                return false;
            }

            if (!Pbkdf2HashingUtil.Verify(password, configuredPasswordPhc))
            {
                _logger.LogWarning("Invalid Basic Auth password provided");
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