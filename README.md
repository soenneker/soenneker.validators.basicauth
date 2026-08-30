[![](https://img.shields.io/nuget/v/soenneker.validators.basicauth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.basicauth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.basicauth/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.validators.basicauth/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.validators.basicauth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.basicauth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.basicauth/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.validators.basicauth/actions/workflows/codeql.yml)

# Soenneker.Validators.BasicAuth

Validates HTTP Basic Authentication credentials against a fixed-cost username comparison and a PBKDF2 PHC password hash.

## Install

```bash
dotnet add package Soenneker.Validators.BasicAuth
```

## Registration

```csharp
using Soenneker.Validators.BasicAuth.Registrars;
using Microsoft.Extensions.DependencyInjection;

services.AddBasicAuthValidatorAsSingleton();
```

The validator is stateless, so singleton registration is appropriate for most applications. `AddBasicAuthValidatorAsScoped()` is also available.

## Configuration

```json
{
  "BasicAuth": {
    "Username": "integration-client",
    "PasswordPhc": "<PBKDF2 PHC hash>"
  }
}
```

Generate and store the PHC hash rather than a plaintext password:

```csharp
using Soenneker.Hashing.Pbkdf2;

string passwordPhc = Pbkdf2HashingUtil.Hash("replace-with-secret-input");
```

Keep the resulting configuration value in a secret store. The validator reads `BasicAuth:Username` and `BasicAuth:PasswordPhc` when the corresponding method argument is null.

## Validate a request

```csharp
using Soenneker.Validators.BasicAuth.Abstract;

if (!validator.ValidateSafe(httpContext))
{
    httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
    return;
}
```

`ValidateSafe` returns `false` when the request lacks parseable Basic credentials or the username/password does not match. Required-configuration failures and invalid PHC data still throw; “safe” applies to request authentication failures, not application misconfiguration.

Use `Validate` when invalid request credentials should throw `UnauthorizedAccessException`:

```csharp
validator.Validate(httpContext);
```

Both methods return `true` on success and use the same generic `"Invalid credentials"` exception message for strict request failures.

## Per-call overrides

```csharp
bool valid = validator.ValidateSafe(
    httpContext,
    configuredUsername: expectedUsername,
    configuredPasswordPhc: expectedPasswordPhc);
```

Overrides take precedence independently. A null argument falls back to configuration; it does not disable that credential check.

## Security boundaries

Basic Authentication transmits a reusable username and password on every request. Require TLS, apply rate limiting where credentials can be guessed, and never log the authorization header or plaintext password. This validator clears the parser's temporary credential buffer after each attempt, compares usernames with fixed-cost UTF-8 comparison, and verifies passwords against the configured PBKDF2 PHC hash.

The validator authenticates one configured credential pair. It does not issue a challenge header, create a `ClaimsPrincipal`, authorize roles, rotate secrets, or replace ASP.NET Core authentication middleware when a full authentication scheme is needed.
