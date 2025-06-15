using AWS.EncryptionSDK;
using AWS.EncryptionSDK.Core;
using System.Security.Cryptography;
using System.Text;

namespace DotNext2025.Benchmarks.Examples;

internal static class RsaExample
{
    public static void Run()
    {
        var length = 10;
        var algorithmSuiteId = AlgorithmSuiteId.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;

        var data = Enumerable.Repeat(0, length).Select(e => (byte)Random.Shared.Next(256)).ToArray();
        Console.WriteLine($"Original: {Convert.ToBase64String(data)}");

        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText("vault.private"));

        var publicKey = new MemoryStream(Encoding.UTF8.GetBytes(ExportPublicKey(rsa)));
        var privateKey = new MemoryStream(Encoding.UTF8.GetBytes(ExportPrivateKey(rsa)));
        var rsaCreateKeyringInput = new CreateRawRsaKeyringInput
        {
            KeyNamespace = "HSM_01",
            KeyName = "RSA_2048_06",
            PaddingScheme = PaddingScheme.OAEP_SHA256_MGF1,
            PublicKey = publicKey,
            PrivateKey = privateKey
        };
        var rsaMaterialProviders = AwsCryptographicMaterialProvidersFactory.CreateDefaultAwsCryptographicMaterialProviders();
        var rsaKeyring = rsaMaterialProviders.CreateRawRsaKeyring(rsaCreateKeyringInput);

        var encryptInput = new EncryptInput
        {
            Plaintext = new MemoryStream(data),
            Keyring = rsaKeyring,
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
            Keyring = rsaKeyring
        };

        var decryptOutput = encryptionSdk.Decrypt(decryptInput);

        Console.WriteLine($"Decrypted: {Convert.ToBase64String(decryptOutput.Plaintext.ToArray())}");
    }

    private static string ExportPublicKey(RSA csp)
    {
        StringWriter outputStream = new StringWriter();
        var parameters = csp.ExportParameters(false);
        using (var stream = new MemoryStream())
        {
            var writer = new BinaryWriter(stream);
            writer.Write((byte)0x30); // SEQUENCE
            using (var innerStream = new MemoryStream())
            {
                var innerWriter = new BinaryWriter(innerStream);
                innerWriter.Write((byte)0x30); // SEQUENCE
                EncodeLength(innerWriter, 13);
                innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                EncodeLength(innerWriter, rsaEncryptionOid.Length);
                innerWriter.Write(rsaEncryptionOid);
                innerWriter.Write((byte)0x05); // NULL
                EncodeLength(innerWriter, 0);
                innerWriter.Write((byte)0x03); // BIT STRING
                using (var bitStringStream = new MemoryStream())
                {
                    var bitStringWriter = new BinaryWriter(bitStringStream);
                    bitStringWriter.Write((byte)0x00); // # of unused bits
                    bitStringWriter.Write((byte)0x30); // SEQUENCE
                    using (var paramsStream = new MemoryStream())
                    {
                        var paramsWriter = new BinaryWriter(paramsStream);
                        EncodeIntegerBigEndian(paramsWriter, parameters.Modulus!); // Modulus
                        EncodeIntegerBigEndian(paramsWriter, parameters.Exponent!); // Exponent
                        var paramsLength = (int)paramsStream.Length;
                        EncodeLength(bitStringWriter, paramsLength);
                        bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                    }
                    var bitStringLength = (int)bitStringStream.Length;
                    EncodeLength(innerWriter, bitStringLength);
                    innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                }
                var length = (int)innerStream.Length;
                EncodeLength(writer, length);
                writer.Write(innerStream.GetBuffer(), 0, length);
            }

            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            // WriteLine terminates with \r\n, we want only \n
            outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                outputStream.Write("\n");
            }
            outputStream.Write("-----END PUBLIC KEY-----");
        }

        return outputStream.ToString();
    }

    private static string ExportPrivateKey(RSA csp)
    {
        StringWriter outputStream = new StringWriter();
        var parameters = csp.ExportParameters(true);
        using (var stream = new MemoryStream())
        {
            var writer = new BinaryWriter(stream);
            writer.Write((byte)0x30); // SEQUENCE
            using (var innerStream = new MemoryStream())
            {
                var innerWriter = new BinaryWriter(innerStream);
                EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                EncodeIntegerBigEndian(innerWriter, parameters.Modulus!);
                EncodeIntegerBigEndian(innerWriter, parameters.Exponent!);
                EncodeIntegerBigEndian(innerWriter, parameters.D!);
                EncodeIntegerBigEndian(innerWriter, parameters.P!);
                EncodeIntegerBigEndian(innerWriter, parameters.Q!);
                EncodeIntegerBigEndian(innerWriter, parameters.DP!);
                EncodeIntegerBigEndian(innerWriter, parameters.DQ!);
                EncodeIntegerBigEndian(innerWriter, parameters.InverseQ!);
                var length = (int)innerStream.Length;
                EncodeLength(writer, length);
                writer.Write(innerStream.GetBuffer(), 0, length);
            }

            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            // WriteLine terminates with \r\n, we want only \n
            outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                outputStream.Write("\n");
            }
            outputStream.Write("-----END RSA PRIVATE KEY-----");
        }

        return outputStream.ToString();
    }

    private static void EncodeLength(BinaryWriter stream, int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
        if (length < 0x80)
        {
            // Short form
            stream.Write((byte)length);
        }
        else
        {
            // Long form
            var temp = length;
            var bytesRequired = 0;
            while (temp > 0)
            {
                temp >>= 8;
                bytesRequired++;
            }
            stream.Write((byte)(bytesRequired | 0x80));
            for (var i = bytesRequired - 1; i >= 0; i--)
            {
                stream.Write((byte)(length >> 8 * i & 0xff));
            }
        }
    }

    private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
    {
        stream.Write((byte)0x02); // INTEGER
        var prefixZeros = 0;
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != 0) break;
            prefixZeros++;
        }

        if (value.Length - prefixZeros == 0)
        {
            EncodeLength(stream, 1);
            stream.Write((byte)0);
        }
        else
        {
            if (forceUnsigned && value[prefixZeros] > 0x7f)
            {
                // Add a prefix zero to force unsigned if the MSB is 1
                EncodeLength(stream, value.Length - prefixZeros + 1);
                stream.Write((byte)0);
            }
            else
            {
                EncodeLength(stream, value.Length - prefixZeros);
            }

            for (var i = prefixZeros; i < value.Length; i++)
            {
                stream.Write(value[i]);
            }
        }
    }
}
