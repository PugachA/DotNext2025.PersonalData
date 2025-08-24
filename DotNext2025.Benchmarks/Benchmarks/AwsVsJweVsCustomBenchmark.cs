using AWS.EncryptionSDK;
using AWS.EncryptionSDK.Core;
using BenchmarkDotNet.Attributes;
using DotNext2025.PersonalData.Cryptography;
using Jose;
using Org.BouncyCastle.Security;

namespace DotNext2025.Benchmarks.Benchmarks;

[MemoryDiagnoser]
public class AwsVsJweVsCustomBenchmark
{
    [Params(10)]
    public int length;

    private byte[] data = null!;
    private byte[] aesKey = null!;
    private IKeyring aesKeyring = null!;
    private AesGcmEncryptor aesGcmEncryptor = null!;

    [GlobalSetup]
    public void Setup()
    {
        data = Enumerable.Repeat(0, length).Select(e => (byte)Random.Shared.Next(256)).ToArray();

        var aesMaterialProviders = AwsCryptographicMaterialProvidersFactory.CreateDefaultAwsCryptographicMaterialProviders();
        aesKey = GeneratorUtilities.GetKeyGenerator("AES256").GenerateKey();
        var aesWrappingKey = new MemoryStream(aesKey);
        var createKeyringInput = new CreateRawAesKeyringInput
        {
            KeyNamespace = "HSM_01",
            KeyName = "AES_256_012",
            WrappingKey = aesWrappingKey,
            WrappingAlg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
        };

        aesKeyring = aesMaterialProviders.CreateRawAesKeyring(createKeyringInput);

        aesGcmEncryptor = new AesGcmEncryptor(aesKey, 12, 16);
    }

    [Benchmark]
    public void UseAws_ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY()
    {
        UseAws(AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY);
    }

    [Benchmark]
    public void UseJwe_A256GCMKW()
    {
        UseJwe(JweAlgorithm.A256GCMKW);
    }

    [Benchmark]
    public void UseCustom_Aes256Gcm()
    {
        var encryptedData = aesGcmEncryptor.Encrypt(data);
        var decryptedData = aesGcmEncryptor.Decrypt(encryptedData);
    }

    private void UseAws(AlgorithmSuiteId algorithmSuiteId)
    {
        var encryptInput = new EncryptInput
        {
            Plaintext = new MemoryStream(data),
            Keyring = aesKeyring,
            AlgorithmSuiteId = algorithmSuiteId
        };

        var config = new AwsEncryptionSdkConfig();

        if (encryptInput.AlgorithmSuiteId == AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
            || encryptInput.AlgorithmSuiteId == AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384)
            config.CommitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
        else
            config.CommitmentPolicy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT;

        var encryptionSdk = AwsEncryptionSdkFactory.CreateAwsEncryptionSdk(config);

        var encryptOutput = encryptionSdk.Encrypt(encryptInput);

        var decryptInput = new DecryptInput
        {
            Ciphertext = encryptOutput.Ciphertext,
            Keyring = aesKeyring
        };

        var decryptOutput = encryptionSdk.Decrypt(decryptInput);
    }

    private void UseJwe(JweAlgorithm jweAlgorithm)
    {
        var encrypted = JWE.EncryptBytes(
            data,
            new[] { new JweRecipient(jweAlgorithm, aesKey) },
            JweEncryption.A256GCM,
            mode: SerializationMode.Compact);

        var decryptOutput = JWE.Decrypt(encrypted, aesKey);
    }
}
