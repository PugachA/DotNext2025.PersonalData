using DotNext2025.PersonalData.Core;

namespace DotNext2025.PersonalData.Cryptography;
public static class EncryptorFactory
{
    public static IEncryptor CreateEncryptor(EncryptionKey key, EncryptionAlgorithm algorithm) => algorithm switch
    {
        EncryptionAlgorithm.Aes256GcmIv96Tag128 => CreateAesGcm(key, 12, 16),
        _ => throw new ArgumentException($"Not supported algorithm {algorithm}")
    };

    private static AesGcmEncryptor CreateAesGcm(EncryptionKey key, byte nonceByteSize, byte tagByteSize)
    {
        if (key.Type != EncryptionKeyType.Aes256Gcm96)
            throw new ArgumentException($"Invalid key type {key.Type}. Support only {EncryptionKeyType.Aes256Gcm96}");

        return new AesGcmEncryptor(key.Key, nonceByteSize, tagByteSize);
    }
}
