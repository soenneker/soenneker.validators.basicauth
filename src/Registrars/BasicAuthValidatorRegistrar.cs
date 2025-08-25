using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Validators.BasicAuth.Abstract;

namespace Soenneker.Validators.BasicAuth.Registrars;

/// <summary>
/// A lightweight validation module for validating HTTP Basic Authentication credentials.
/// </summary>
public static class BasicAuthValidatorRegistrar
{
    /// <summary>
    /// Adds <see cref="IBasicAuthValidator"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddBasicAuthValidatorAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<IBasicAuthValidator, BasicAuthValidator>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="IBasicAuthValidator"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddBasicAuthValidatorAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<IBasicAuthValidator, BasicAuthValidator>();

        return services;
    }
}
