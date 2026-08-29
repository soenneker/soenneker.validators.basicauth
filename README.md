[![](https://img.shields.io/nuget/v/soenneker.validators.basicauth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.basicauth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.basicauth/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.validators.basicauth/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.validators.basicauth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.basicauth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.basicauth/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.validators.basicauth/actions/workflows/codeql.yml)

# Soenneker.Validators.BasicAuth

A lightweight validation module for validating HTTP Basic Authentication credentials.

## Install

```bash
dotnet add package Soenneker.Validators.BasicAuth
```

## Quick start

```csharp
using Soenneker.Validators.BasicAuth.Registrars;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var result = services.AddBasicAuthValidatorAsSingleton();
```

Adds `IBasicAuthValidator` as a singleton service.

## What you get

- `IBasicAuthValidator` — A lightweight validation module for validating HTTP Basic Authentication credentials.
- `BasicAuthValidatorRegistrar` — A lightweight validation module for validating HTTP Basic Authentication credentials.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `IBasicAuthValidator.Validate(httpContext, configuredUsername, configuredPasswordPhc)` | Strict validator: throws UnauthorizedAccessException on any failure. | true if strict validator: throws UnauthorizedAccessException on any failure; otherwise, false. |
| `IBasicAuthValidator.ValidateSafe(httpContext, configuredUsername, configuredPasswordPhc)` | Validates Basic credentials and returns false instead of throwing when credentials or configuration are invalid. | true if the supplied credentials match the configured credentials; otherwise, false. |
| `BasicAuthValidatorRegistrar.AddBasicAuthValidatorAsSingleton(services)` | Adds `IBasicAuthValidator` as a singleton service. | The same service collection, so additional registrations can be chained. |
| `BasicAuthValidatorRegistrar.AddBasicAuthValidatorAsScoped(services)` | Adds `IBasicAuthValidator` as a scoped service. | The same service collection, so additional registrations can be chained. |
