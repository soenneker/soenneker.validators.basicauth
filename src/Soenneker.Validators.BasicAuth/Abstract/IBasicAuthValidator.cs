using Microsoft.AspNetCore.Http;
using Soenneker.Validators.Validator.Abstract;

namespace Soenneker.Validators.BasicAuth.Abstract;

/// <summary>
/// A lightweight validation module for validating HTTP Basic Authentication credentials.
/// </summary>
public interface IBasicAuthValidator : IValidator
{
    /// <summary>
    /// Strict validator: throws UnauthorizedAccessException on any failure.
    /// </summary>
    /// <param name="httpContext">HTTP context containing the Basic authentication request.</param>
    /// <param name="configuredUsername">Expected username, or null when username validation is disabled.</param>
    /// <param name="configuredPasswordPhc">Expected password hash in PHC format, or null when password validation is disabled.</param>
    /// <returns>true if strict validator: throws UnauthorizedAccessException on any failure; otherwise, false.</returns>
    bool Validate(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null);

    /// <summary>
    /// Validates Basic credentials and returns false instead of throwing when credentials or configuration are invalid.
    /// </summary>
    /// <param name="httpContext">HTTP context containing the Basic authentication request.</param>
    /// <param name="configuredUsername">Expected username, or null when username validation is disabled.</param>
    /// <param name="configuredPasswordPhc">Expected password hash in PHC format, or null when password validation is disabled.</param>
    /// <returns>true if the supplied credentials match the configured credentials; otherwise, false.</returns>
    bool ValidateSafe(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null);
}
