using AWS.EncryptionSDK;
using AWS.EncryptionSDK.Core;
using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Security;

namespace DotNext2025.Benchmarks.Benchmarks;

[MemoryDiagnoser]
public class AwsAlgorithmSuiteIdBenchmark
{
    [Params(10)]
    public int length;

    [ParamsSource(nameof(AlgorithmSuiteIds))]
    public AlgorithmSuiteId algorithmSuiteId = default!;

    private byte[] data = null!;
    private IKeyring aesKeyring = null!;

    public IEnumerable<AlgorithmSuiteId> AlgorithmSuiteIds()
    {
        yield return AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;
        yield return AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256;
        yield return AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384;
        yield return AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
        yield return AlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384;
    }

    [GlobalSetup]
    public void Setup()
    {
        data = Enumerable.Repeat(0, length).Select(e => (byte)Random.Shared.Next(256)).ToArray();

        var aesMaterialProviders = AwsCryptographicMaterialProvidersFactory.CreateDefaultAwsCryptographicMaterialProviders();
        var aesWrappingKey = new MemoryStream(GeneratorUtilities.GetKeyGenerator("AES256").GenerateKey());
        var createKeyringInput = new CreateRawAesKeyringInput
        {
            KeyNamespace = "HSM_01",
            KeyName = "AES_256_012",
            WrappingKey = aesWrappingKey,
            WrappingAlg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
        };

        aesKeyring = aesMaterialProviders.CreateRawAesKeyring(createKeyringInput);
    }

    [Benchmark]
    public void UseAes()
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
}
