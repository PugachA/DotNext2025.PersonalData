namespace DotNext2025.PersonalData.Cryptography.Vault;
public class CachedVaultConfig : VaultConfig
{
    public TimeSpan LatestKeyCacheExpiration { get; set; }
}
