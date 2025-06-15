using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.SecretsEngines.Transit;

namespace DotNext2025.Benchmarks.Examples;

internal class VaultExample
{
    public static async Task Run()
    {
        var authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
        var vaultClient = new VaultClient(new VaultClientSettings("http://localhost:8201", authMethod));

        var exportedKeyInfo = await vaultClient.V1.Secrets.Transit.ExportKeyAsync(
            TransitKeyCategory.encryption_key,
            "test-aes",
            "latest",
            "transit/");

        Console.WriteLine(string.Join(Environment.NewLine, exportedKeyInfo.Data.Keys));
    }
}
