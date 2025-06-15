using Microsoft.Extensions.Logging;
using VaultSharp.V1.AuthMethods;

namespace DotNext2025.PersonalData.Cryptography.Vault;
public static class VaultKmsProviderFactory
{
    public static IKmsProvider CreateCachedProvider(
        CachedVaultConfig config,
        IAuthMethodInfo authMethod,
        ILoggerFactory loggerFactory)
    {
        var provider = new VaultKmsProvider(config, authMethod, loggerFactory.CreateLogger<VaultKmsProvider>());

        return new CachedKmsProvider(provider, config.LatestKeyCacheExpiration);
    }
}
