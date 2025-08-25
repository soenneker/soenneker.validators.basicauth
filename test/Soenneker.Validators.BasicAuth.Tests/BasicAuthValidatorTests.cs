using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Soenneker.Hashing.Pbkdf2;
using Soenneker.Tests.FixturedUnit;
using Soenneker.Validators.BasicAuth.Abstract;
using System;
using System.Collections.Generic;
using System.Text;
using AwesomeAssertions;
using Xunit;

namespace Soenneker.Validators.BasicAuth.Tests;

[Collection("Collection")]
public sealed class BasicAuthValidatorTests : FixturedUnitTest
{
    private readonly IBasicAuthValidator _util;

    public BasicAuthValidatorTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
        _util = Resolve<IBasicAuthValidator>(true);
    }

    [Fact]
    public void Default()
    {
    }

    private static IConfiguration BuildConfig(string username, string passwordPlaintext)
    {
        string phc = Pbkdf2HashingUtil.Hash(passwordPlaintext);

        var dict = new Dictionary<string, string?>
        {
            ["BasicAuth:Username"] = username,
            ["BasicAuth:PasswordPch"] = phc
        };

        return new ConfigurationBuilder().AddInMemoryCollection(dict!).Build();
    }

    private static DefaultHttpContext BuildContext(string? username, string? password)
    {
        var ctx = new DefaultHttpContext();

        if (username is not null && password is not null)
        {
            string basic = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{password}"));
            ctx.Request.Headers["Authorization"] = $"Basic {basic}";
        }

        return ctx;
    }

    private static BasicAuthValidator CreateSut(IConfiguration cfg)
    {
        return new BasicAuthValidator(cfg, NullLogger<BasicAuthValidator>.Instance);
    }

    [Fact]
    public void Validate_Success_Config_ReturnsTrue()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, p);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.Validate(ctx).Should().BeTrue();
    }

    [Fact]
    public void Validate_InvalidHeader_Config_ThrowsUnauthorized()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(null, null);

        BasicAuthValidator sut = CreateSut(cfg);

        Action act = () => sut.Validate(ctx);
        act.Should().Throw<UnauthorizedAccessException>().WithMessage("Invalid credentials");
    }

    [Fact]
    public void Validate_BadUsername_Config_ThrowsUnauthorized()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext("wrongUser", p);

        BasicAuthValidator sut = CreateSut(cfg);

        Action act = () => sut.Validate(ctx);
        act.Should().Throw<UnauthorizedAccessException>().WithMessage("Invalid credentials");
    }

    [Fact]
    public void Validate_BadPassword_Config_ThrowsUnauthorized()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, "wrongPass");

        BasicAuthValidator sut = CreateSut(cfg);

        Action act = () => sut.Validate(ctx);
        act.Should().Throw<UnauthorizedAccessException>().WithMessage("Invalid credentials");
    }

    [Fact]
    public void ValidateSafe_Success_Config_ReturnsTrue()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, p);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeTrue();
    }

    [Fact]
    public void ValidateSafe_InvalidHeader_Config_ReturnsFalse()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(null, null);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeFalse();
    }

    [Fact]
    public void ValidateSafe_BadUsername_Config_ReturnsFalse()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext("wrongUser", p);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeFalse();
    }

    [Fact]
    public void ValidateSafe_BadPassword_Config_ReturnsFalse()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, "wrongPass");

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeFalse();
    }

    [Fact]
    public void Validate_Overrides_TakePrecedence()
    {
        // Wrong config
        IConfiguration cfg = BuildConfig("configUser", "configPass");

        const string overrideUser = "overrideUser";
        const string overridePass = "overridePass";
        string overridePhc = Pbkdf2HashingUtil.Hash(overridePass);

        DefaultHttpContext ctx = BuildContext(overrideUser, overridePass);
        BasicAuthValidator sut = CreateSut(cfg);

        sut.Validate(ctx, configuredUsername: overrideUser, configuredPasswordPhc: overridePhc).Should().BeTrue();
    }

    [Fact]
    public void ValidateSafe_Overrides_BadPassword_ReturnsFalse()
    {
        IConfiguration cfg = BuildConfig("configUser", "configPass");

        const string overrideUser = "overrideUser";
        const string overridePass = "overridePass";
        string overridePhc = Pbkdf2HashingUtil.Hash(overridePass);

        DefaultHttpContext ctx = BuildContext(overrideUser, "wrongPass");
        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx, configuredUsername: overrideUser, configuredPasswordPhc: overridePhc).Should().BeFalse();
    }
}