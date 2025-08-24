namespace DotNext2025.PersonalData.Cryptography;
public class VaultConfig
{
    public string VaultServer { get; set; } = null!;
    public string MountPoint { get; set; } = null!;
    public TimeSpan? Timeout { get; set; }
    public bool AutoRefreshToken { get; set; } = true;
    public int MaxRetryCount { get; set; } = 3;
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(5);
}
