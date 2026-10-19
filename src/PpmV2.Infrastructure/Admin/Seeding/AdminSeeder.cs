using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PpmV2.Domain.Users;
using PpmV2.Infrastructure.Identity;
using PpmV2.Infrastructure.Persistence;

namespace PpmV2.Infrastructure.Admin.Seeding;

// <summary>
/// Seeds an initial admin account based on configuration.
/// </summary>
/// <remarks>
/// This seeder is:
/// - opt-in via configuration (AdminSeed:Enabled)
/// - idempotent (can be executed multiple times safely)
/// - responsible for enforcing minimal invariants for the admin user and profile
///
/// The goal is to ensure that an administrator exists in non-production environments
/// (or in controlled production setups) without manual database manipulation.
/// </remarks>
public static class AdminSeeder
{
    public static async Task SeedAsync(
        UserManager<AppUser> userManager,
        AppDbContext dbContext,
        IConfiguration configuration,
        TimeProvider timeProvider,
        ILogger logger)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var section = configuration.GetSection("AdminSeed");

        // Config flag to avoid accidental seeding in unwanted environments.
        var enabled = bool.TryParse(section["Enabled"], out var isEnabled) && isEnabled;
        if (!enabled)
        {
            logger.LogInformation("AdminSeeder: disabled.");
            return;
        }

        var email = section["Email"];
        var password = section["Password"];

        if (string.IsNullOrWhiteSpace(password))
        {
            logger.LogInformation("AdminSeeder: Password missing. Skipping seed.");
            return;
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            logger.LogWarning("AdminSeeder: Email missing. Skipping seed.");
            return;
        }

        // Find or create the admin identity user.
        var user = await userManager.FindByEmailAsync(email);
        var adminAlreadyExisted = user is not null;

        if (user == null)
        {
            user = new AppUser
            {
                UserName = email,
                Email = email,
                IsActive = true,
                Status = UserStatus.Approved,
                Role = UserRole.Admin,
                IsProfileCompleted = true
            };

            var createResult = await userManager.CreateAsync(user, password);
            if (!createResult.Succeeded)
            {
                var errors = string.Join("; ", createResult.Errors.Select(e => e.Description));
                logger.LogError("AdminSeeder: failed to create admin user. Errors: {Errors}", errors);
                return;
            }

            logger.LogInformation("AdminSeeder: created admin user {Email}", email);
        }

        // Ensure invariants for existing or newly created user (idempotent enforcement).
        var changed = false;

        if (user.Role != UserRole.Admin) { user.Role = UserRole.Admin; changed = true; }
        if (user.Status != UserStatus.Approved) { user.Status = UserStatus.Approved; changed = true; }
        if (!user.IsActive) { user.IsActive = true; changed = true; }
        if (!user.IsProfileCompleted) { user.IsProfileCompleted = true; changed = true; }

        if (changed)
        {
            var updateResult = await userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                var errors = string.Join("; ", updateResult.Errors.Select(e => e.Description));
                logger.LogError("AdminSeeder: failed to update admin user. Errors: {Errors}", errors);
                return;
            }
        }

        // Ensure profile exists for the admin user (Identity <-> UserProfile 1:1).
        var profileExists = await dbContext.UserProfiles
            .AnyAsync(p => p.IdentityUserId == user.Id);

        if (!profileExists)
        {
            dbContext.UserProfiles.Add(new UserProfile
            {
                IdentityUserId = user.Id,
                Firstname = "System",
                Lastname = "Administrator",
                Email = user.Email!,
                IsActive = true,
                CreatedAt = now,
                UpdatedAt = now
            });

            await dbContext.SaveChangesAsync();
            logger.LogInformation("AdminSeeder: created admin profile for {Email}", email);
        }
        else
        {
            // Optional: enforce profile display names only when missing (avoid overwriting real data).
            var profile = await dbContext.UserProfiles.FirstAsync(p => p.IdentityUserId == user.Id);

            var pChanged = false;
            if (string.IsNullOrWhiteSpace(profile.Firstname)) { profile.Firstname = "System"; pChanged = true; }
            if (string.IsNullOrWhiteSpace(profile.Lastname)) { profile.Lastname = "Administrator"; pChanged = true; }
            if (string.IsNullOrWhiteSpace(profile.Email)) {
                if (!string.IsNullOrWhiteSpace(user.Email))
                {
                    profile.Email = user.Email;
                    pChanged = true;
                }
                else
                {
                    logger.LogWarning("AdminSeeder: user.Email is null/empty for admin user {UserId}. Profile email not updated.", user.Id);
                }
            }


            if (pChanged)
            {
                profile.UpdatedAt = now;
                await dbContext.SaveChangesAsync();
                logger.LogInformation("AdminSeeder: updated admin profile for {Email}", email);
            }
        }

        if (!adminAlreadyExisted)
            return;

        var resetPasswordOnStart = bool.TryParse(section["ResetPasswordOnStart"], out var shouldReset) && shouldReset;
        if (!resetPasswordOnStart)
            return;

        await ResetExistingAdminPasswordAsync(userManager, dbContext, user, password, timeProvider, logger);
    }

    private static async Task ResetExistingAdminPasswordAsync(
        UserManager<AppUser> userManager,
        AppDbContext dbContext,
        AppUser user,
        string configuredPassword,
        TimeProvider timeProvider,
        ILogger logger)
    {
        if (await userManager.CheckPasswordAsync(user, configuredPassword))
            return;

        if (await userManager.HasPasswordAsync(user))
        {
            var removeResult = await userManager.RemovePasswordAsync(user);
            if (!removeResult.Succeeded)
            {
                LogIdentityErrors(logger, "AdminSeeder: failed to remove admin password.", removeResult);
                return;
            }
        }

        var addResult = await userManager.AddPasswordAsync(user, configuredPassword);
        if (!addResult.Succeeded)
        {
            LogIdentityErrors(logger, "AdminSeeder: failed to set admin password.", addResult);
            return;
        }

        var stampResult = await userManager.UpdateSecurityStampAsync(user);
        if (!stampResult.Succeeded)
            LogIdentityErrors(logger, "AdminSeeder: failed to update admin security stamp.", stampResult);

        var revokedAt = timeProvider.GetUtcNow().UtcDateTime;
        var tokens = await dbContext.RefreshTokens
            .Where(t => t.UserId == user.Id && t.RevokedAt == null)
            .ToListAsync();

        foreach (var token in tokens)
            token.RevokedAt = revokedAt;

        if (tokens.Count > 0)
            await dbContext.SaveChangesAsync();

        if (stampResult.Succeeded)
            logger.LogInformation("Admin password was reset via AdminSeed:ResetPasswordOnStart");
    }

    private static void LogIdentityErrors(ILogger logger, string message, IdentityResult result)
    {
        var errors = string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Description}"));
        logger.LogError("{Message} Errors: {Errors}", message, errors);
    }
}

