using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PpmV2.Domain.Auth;
using PpmV2.Domain.Users;
using PpmV2.Infrastructure.Admin.Seeding;
using PpmV2.Infrastructure.Identity;
using PpmV2.Infrastructure.Persistence;

namespace PpmV2.Tests.Admin;

public class AdminSeederTests
{
    private const string ExistingPassword = "Pass123$";
    private const string ReplacementPassword = "Pass456$";

    [Fact]
    public async Task ResetPasswordOnStart_ReplacesPasswordAndRevokesThatUsersRefreshTokens()
    {
        await using var db = CreateDb();
        var userManager = CreateUserManager(db);
        var admin = await CreateAdminAsync(userManager, ExistingPassword);
        var other = await CreateAdminAsync(userManager, ExistingPassword);
        var stampBefore = admin.SecurityStamp;

        db.RefreshTokens.AddRange(
            TokenFor(admin.Id),
            TokenFor(other.Id));
        await db.SaveChangesAsync();

        await AdminSeeder.SeedAsync(
            userManager,
            db,
            Config(admin.Email!, ReplacementPassword, resetPasswordOnStart: true),
            TimeProvider.System,
            NullLogger.Instance);

        Assert.False(await userManager.CheckPasswordAsync(admin, ExistingPassword));
        Assert.True(await userManager.CheckPasswordAsync(admin, ReplacementPassword));
        Assert.NotEqual(stampBefore, admin.SecurityStamp);

        var adminToken = await db.RefreshTokens.SingleAsync(t => t.UserId == admin.Id);
        var otherToken = await db.RefreshTokens.SingleAsync(t => t.UserId == other.Id);
        Assert.NotNull(adminToken.RevokedAt);
        Assert.Null(otherToken.RevokedAt);
    }

    [Fact]
    public async Task ResetPasswordOnStart_DoesNothingWhenPasswordAlreadyMatches()
    {
        await using var db = CreateDb();
        var userManager = CreateUserManager(db);
        var admin = await CreateAdminAsync(userManager, ExistingPassword);
        var hashBefore = admin.PasswordHash;
        var stampBefore = admin.SecurityStamp;
        db.RefreshTokens.Add(TokenFor(admin.Id));
        await db.SaveChangesAsync();

        await AdminSeeder.SeedAsync(
            userManager,
            db,
            Config(admin.Email!, ExistingPassword, resetPasswordOnStart: true),
            TimeProvider.System,
            NullLogger.Instance);

        Assert.Equal(hashBefore, admin.PasswordHash);
        Assert.Equal(stampBefore, admin.SecurityStamp);
        Assert.Null((await db.RefreshTokens.SingleAsync()).RevokedAt);
    }

    [Fact]
    public async Task ResetPasswordOnStart_DoesNothingWhenFlagIsFalse()
    {
        await using var db = CreateDb();
        var userManager = CreateUserManager(db);
        var admin = await CreateAdminAsync(userManager, ExistingPassword);
        var hashBefore = admin.PasswordHash;

        await AdminSeeder.SeedAsync(
            userManager,
            db,
            Config(admin.Email!, ReplacementPassword, resetPasswordOnStart: false),
            TimeProvider.System,
            NullLogger.Instance);

        Assert.Equal(hashBefore, admin.PasswordHash);
        Assert.True(await userManager.CheckPasswordAsync(admin, ExistingPassword));
        Assert.False(await userManager.CheckPasswordAsync(admin, ReplacementPassword));
    }

    private static AppDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new AppDbContext(options);
    }

    private static UserManager<AppUser> CreateUserManager(AppDbContext db)
    {
        var store = new UserStore<AppUser, AppRole, AppDbContext, Guid>(db);
        return new UserManager<AppUser>(
            store,
            Options.Create(new IdentityOptions()),
            new PasswordHasher<AppUser>(),
            [new UserValidator<AppUser>()],
            [new PasswordValidator<AppUser>()],
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            new ServiceCollection().BuildServiceProvider(),
            NullLogger<UserManager<AppUser>>.Instance);
    }

    private static async Task<AppUser> CreateAdminAsync(UserManager<AppUser> userManager, string password)
    {
        var email = $"{Guid.NewGuid():N}@example.com";
        var user = new AppUser
        {
            UserName = email,
            Email = email,
            Role = UserRole.Admin,
            Status = UserStatus.Approved,
            IsActive = true,
            IsProfileCompleted = true
        };

        var result = await userManager.CreateAsync(user, password);
        Assert.True(result.Succeeded);

        return user;
    }

    private static IConfiguration Config(string email, string password, bool resetPasswordOnStart) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AdminSeed:Enabled"] = "true",
                ["AdminSeed:Email"] = email,
                ["AdminSeed:Password"] = password,
                ["AdminSeed:ResetPasswordOnStart"] = resetPasswordOnStart ? "true" : "false"
            })
            .Build();

    private static RefreshToken TokenFor(Guid userId) => new()
    {
        UserId = userId,
        Token = Guid.NewGuid().ToString("N"),
        CreatedAt = DateTime.UtcNow,
        ExpiresAt = DateTime.UtcNow.AddDays(7)
    };
}
