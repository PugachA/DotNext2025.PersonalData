namespace DotNext2025.PersonalData.Cryptography;
public interface IKmsProvider
{
    Task<EncryptionKey> GetEncryptionKey(string keyName, string keyVersion, CancellationToken ct = default);
    Task<EncryptionKey> GetLatestEncryptionKey(string keyName, CancellationToken ct = default);
}

public record EncryptionKey(string Name, string Version, EncryptionKeyType Type, byte[] Key);

public enum EncryptionKeyType
{
    Aes256Gcm96 = 1
}
