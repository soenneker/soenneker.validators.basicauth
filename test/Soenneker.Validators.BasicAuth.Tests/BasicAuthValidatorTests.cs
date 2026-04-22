using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Soenneker.Hashing.Pbkdf2;
using Soenneker.Tests.HostedUnit;
using Soenneker.Validators.BasicAuth.Abstract;
using System;
using System.Collections.Generic;
using System.Text;
using AwesomeAssertions;

namespace Soenneker.Validators.BasicAuth.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class BasicAuthValidatorTests : HostedUnitTest
{
    private readonly IBasicAuthValidator _util;

    public BasicAuthValidatorTests(Host host) : base(host)
    {
        _util = Resolve<IBasicAuthValidator>(true);
    }

    [Test]
    public void Default()
    {
    }

    private static IConfiguration BuildConfig(string username, string passwordPlaintext)
    {
        string phc = Pbkdf2HashingUtil.Hash(passwordPlaintext);

        var dict = new Dictionary<string, string?>
        {
            ["BasicAuth:Username"] = username,
            ["BasicAuth:PasswordPhc"] = phc
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

    [Test]
    public void Validate_Success_Config_ReturnsTrue()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, p);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.Validate(ctx).Should().BeTrue();
    }

    [Test]
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

    [Test]
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

    [Test]
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

    [Test]
    public void ValidateSafe_Success_Config_ReturnsTrue()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, p);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeTrue();
    }

    [Test]
    public void ValidateSafe_InvalidHeader_Config_ReturnsFalse()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(null, null);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeFalse();
    }

    [Test]
    public void ValidateSafe_BadUsername_Config_ReturnsFalse()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext("wrongUser", p);

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeFalse();
    }

    [Test]
    public void ValidateSafe_BadPassword_Config_ReturnsFalse()
    {
        const string u = "admin";
        const string p = "S3cr3t!";
        IConfiguration cfg = BuildConfig(u, p);
        DefaultHttpContext ctx = BuildContext(u, "wrongPass");

        BasicAuthValidator sut = CreateSut(cfg);

        sut.ValidateSafe(ctx).Should().BeFalse();
    }

    [Test]
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

    [Test]
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