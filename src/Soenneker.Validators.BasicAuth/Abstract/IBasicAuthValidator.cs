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
    /// <param name="configuredUsername">An optional expected username override. When null, <c>BasicAuth:Username</c> is required from configuration.</param>
    /// <param name="configuredPasswordPhc">An optional expected PHC password-hash override. When null, <c>BasicAuth:PasswordPhc</c> is required from configuration.</param>
    /// <returns><see langword="true"/> when the supplied credentials match.</returns>
    /// <exception cref="System.UnauthorizedAccessException">Thrown when the authorization header cannot be parsed or either credential does not match.</exception>
    bool Validate(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null);

    /// <summary>
    /// Validates Basic credentials and returns false instead of throwing for a missing, malformed, or non-matching request credential.
    /// </summary>
    /// <param name="httpContext">HTTP context containing the Basic authentication request.</param>
    /// <param name="configuredUsername">An optional expected username override. When null, <c>BasicAuth:Username</c> is required from configuration.</param>
    /// <param name="configuredPasswordPhc">An optional expected PHC password-hash override. When null, <c>BasicAuth:PasswordPhc</c> is required from configuration.</param>
    /// <returns>true if the supplied credentials match the configured credentials; otherwise, false.</returns>
    bool ValidateSafe(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null);
}
