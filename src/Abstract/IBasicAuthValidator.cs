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
    bool Validate(HttpContext httpContext, string? username = null, string? passwordPch = null);

    bool ValidateSafe(HttpContext httpContext, string? username = null, string? passwordPch = null);
}
