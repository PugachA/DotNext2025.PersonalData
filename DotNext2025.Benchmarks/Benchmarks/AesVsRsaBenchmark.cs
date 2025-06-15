using BenchmarkDotNet.Attributes;
using DotNext2025.PersonalData.Core;
using DotNext2025.PersonalData.Cryptography;
using System.Security.Cryptography;

namespace DotNext2025.Benchmarks.Benchmarks;

//[MemoryDiagnoser]
public class AesVsRsaBenchmark
{
    [Params(20)]
    public int Length;

    private byte[] data = null!;
    private IEncryptor aesEncryptor = null!;
    private RSA rsa = null!;

    [GlobalSetup]
    public void Setup()
    {
        data = Enumerable.Repeat(0, Length).Select(e => (byte)Random.Shared.Next(256)).ToArray();

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var encryptionKey = new EncryptionKey("test", "1", EncryptionKeyType.Aes256Gcm96, key);
        aesEncryptor = EncryptorFactory.CreateEncryptor(encryptionKey, EncryptionAlgorithm.Aes256GcmIv96Tag128);

        rsa = RSA.Create(2048);
    }

    [Benchmark(Description = "Aes256GcmIv96Tag128", Baseline = true)]
    public void UseAes256GcmIv96Tag128()
    {
        var encrypted = aesEncryptor.Encrypt(data);
        var decrypted = aesEncryptor.Decrypt(encrypted);
    }

    [Benchmark(Description = "Rsa2048OaepSha256")]
    public void UseRsa2048OaepSha256()
    {
        var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        var decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
    }
}
