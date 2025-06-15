using AWS.EncryptionSDK;
using AWS.EncryptionSDK.Core;
using Org.BouncyCastle.Security;

namespace DotNext2025.Benchmarks.Examples;

internal static class AesExample
{
    public static void Run()
    {
        var length = 10;
        var keyCount = 1;
        var algorithmSuiteId = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;

        var data = Enumerable.Repeat(0, length).Select(e => (byte)Random.Shared.Next(256)).ToArray();
        Console.WriteLine($"Original: {Convert.ToBase64String(data)}");

        var aesMaterialProviders = AwsCryptographicMaterialProvidersFactory.CreateDefaultAwsCryptographicMaterialProviders();

        var keyRings = new List<IKeyring>();
        for (int i = 0; i < keyCount; i++)
        {
            var aesWrappingKey = new MemoryStream(GeneratorUtilities.GetKeyGenerator("AES256").GenerateKey());
            var createKeyringInput = new CreateRawAesKeyringInput
            {
                KeyNamespace = $"HSM_0{i}",
                KeyName = $"AES_256_01{i}",
                WrappingKey = aesWrappingKey,
                WrappingAlg = AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16
            };

            keyRings.Add(aesMaterialProviders.CreateRawAesKeyring(createKeyringInput));
        }

        IKeyring multiKeyring = null!;
        if (keyRings.Count == 1)
            multiKeyring = keyRings.First();

        if (keyRings.Count > 1)
        {
            var createMultiKeyringInput = new CreateMultiKeyringInput();
            createMultiKeyringInput.Generator = keyRings.First();
            createMultiKeyringInput.ChildKeyrings = keyRings.GetRange(1, keyRings.Count - 1);
            multiKeyring = aesMaterialProviders.CreateMultiKeyring(createMultiKeyringInput);
        }

        var encryptInput = new EncryptInput
        {
            Plaintext = new MemoryStream(data),
            Keyring = multiKeyring,
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
            Keyring = multiKeyring
        };

        var decryptOutput = encryptionSdk.Decrypt(decryptInput);
        Console.WriteLine($"Decrypted: {Convert.ToBase64String(decryptOutput.Plaintext.ToArray())}");
    }
}
