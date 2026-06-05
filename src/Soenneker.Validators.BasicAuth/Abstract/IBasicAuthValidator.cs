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
    bool Validate(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null);

    /// <summary>
    /// Executes the validate safe operation.
    /// </summary>
    /// <param name="httpContext">The http context.</param>
    /// <param name="configuredUsername">The configured username.</param>
    /// <param name="configuredPasswordPhc">The configured password phc.</param>
    /// <returns>A value indicating whether the operation succeeded.</returns>
    bool ValidateSafe(HttpContext httpContext, string? configuredUsername = null, string? configuredPasswordPhc = null);
}
