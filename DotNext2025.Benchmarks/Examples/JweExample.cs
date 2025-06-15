using System.Text;
using AESEncryption;
using Iced.Intel;
using Jose;

namespace DotNext2025.Benchmarks.Examples;
internal static class JweExample
{
    public static void Run()
    {
        var length = 10;
        var data = Enumerable.Repeat(0, length).Select(e => (byte)Random.Shared.Next(256)).ToArray();
        var payload = "Hello JWE !";
        var preSharedKey = Convert.FromBase64String("4KoV8mm8QHYuzh6mQAg89P6glC3Pvph3lziTstQP0/Y=");

        // generate JSON encoded token
        var headers = new Dictionary<string, object>() { { "kid", "vault-key" } };
        string token_1 = JWE.Encrypt(
            payload,
            new[] { new JweRecipient(JweAlgorithm.A256GCMKW, preSharedKey, headers) },
            JweEncryption.A256GCM);
        Console.WriteLine($"Encrypt");
        Console.WriteLine(token_1);
        Console.WriteLine($"Length: {token_1.Length}");

        // encrypt binary
        string token_2 = JWE.EncryptBytes(
            Encoding.UTF8.GetBytes(payload),
            new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey) },
            JweEncryption.A256GCM);
        Console.WriteLine($"EncryptBytes");
        Console.WriteLine(token_2);
        Console.WriteLine($"Length: {token_2.Length}");

        string token_3 = JWE.Encrypt(
            payload,
            new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey) },
            JweEncryption.A256GCM,
            mode: SerializationMode.Compact);
        Console.WriteLine($"Encrypt Compact");
        Console.WriteLine(token_3);
        Console.WriteLine($"Length: {token_3.Length}");

        string token_4 = JWE.EncryptBytes(
            Encoding.UTF8.GetBytes(payload),
            new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey) },
            JweEncryption.A256GCM,
            mode: SerializationMode.Compact);
        Console.WriteLine($"EncryptBytes Compact");
        Console.WriteLine(token_4);
        Console.WriteLine($"Length: {token_4.Length}");

        string token_5 = JWE.Encrypt(
            payload,
            new[] { new JweRecipient(JweAlgorithm.A256KW, preSharedKey) },
            JweEncryption.A256GCM,
            mode: SerializationMode.Compact,
            compression: JweCompression.DEF);
        Console.WriteLine($"EncryptBytes Compact Compression");
        Console.WriteLine(token_5);
        Console.WriteLine($"Length: {token_5.Length}");

        Jwk octKey = new Jwk(preSharedKey);
        octKey.Alg = JweAlgorithm.A256KW.ToString();
        octKey.KeyId = "Test";

        var t = JWE.Decrypt(token_4, preSharedKey);
        Console.WriteLine($"Decrypt: {t.AsString()}");
    }
}
