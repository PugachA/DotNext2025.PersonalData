using Microsoft.Extensions.Logging;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token.Models;
using VaultSharp.V1.Commons;
using VaultSharp.V1.SecretsEngines.Transit;

namespace DotNext2025.PersonalData.Cryptography.Vault;
public class VaultKmsProvider : IKmsProvider
{
    private readonly VaultConfig _config;
    private readonly ILogger<VaultKmsProvider> _logger;
    private readonly IVaultClient _vaultClient;
    private Secret<CallingTokenInfo> _token;

    public VaultKmsProvider(
        VaultConfig config, IAuthMethodInfo authMethod, ILogger<VaultKmsProvider> logger)
    {
        _config = config;
        _logger = logger;
        _vaultClient = CreateVaultClient(config, authMethod);
        _token = _vaultClient.V1.Auth.Token.LookupSelfAsync().Result;
        _logger.LogInformation($"Success connect to {config.VaultServer}");
    }

    public async Task<EncryptionKey> GetEncryptionKey(
        string keyName, string keyVersion, CancellationToken ct = default)
    {
        await RefreshToken(ct);

        _logger.LogInformation($"Exporting transit key {keyName} ({keyVersion}) from Vault");
        var exportedKeyInfo = await RetryOnExceptionAsync<Secret<ExportedKeyInfo>, Exception>(
            _config.MaxRetryCount,
            _config.RetryDelay,
            async () => await ExportKey(keyName, keyVersion, ct),
            ct);

        if (exportedKeyInfo.Data.Keys.Count != 1)
            throw new InvalidOperationException($"Export not single key versions. Count={exportedKeyInfo.Data.Keys.Count}");

        var keyType = GetEncryptionKeyType(exportedKeyInfo.Data.Type);
        var versionKeyPair = exportedKeyInfo.Data.Keys.Single();
        var base64Key = versionKeyPair.Value.ToString() ?? throw new NullReferenceException("Can not convert key to string.");
        var key = Convert.FromBase64String(base64Key);

        return new(keyName, versionKeyPair.Key, keyType, key);
    }

    public Task<EncryptionKey> GetLatestEncryptionKey(
        string keyName, CancellationToken ct = default) => GetEncryptionKey(keyName, "latest", ct);

    private async Task<Secret<ExportedKeyInfo>> ExportKey(string keyName, string keyVersion, CancellationToken ct = default)
    {
        try
        {
            return await _vaultClient.V1.Secrets.Transit
                .ExportKeyAsync(TransitKeyCategory.encryption_key, keyName, keyVersion, _config.MountPoint)
                .WithCancellation(ct);
        }
        catch (VaultApiException ex)
        {
            var message = $"{ex.Message}. MountPoint:{_config.MountPoint} KeyName:{keyName} Version:{keyVersion} HttpStatusCode:{ex.HttpStatusCode} StatusCode:{ex.StatusCode}";
            throw new VaultApiException(message, ex);
        }
    }

    private static IVaultClient CreateVaultClient(VaultConfig config, IAuthMethodInfo authMethod)
    {
        if (!Uri.TryCreate(config.VaultServer, UriKind.Absolute, out var _))
            throw new ArgumentException($"{nameof(config.VaultServer)} must be a valid Uri");

        var vaultClientSettings = new VaultClientSettings(config.VaultServer, authMethod)
        {
            VaultServiceTimeout = config.Timeout
        };

        return new VaultClient(vaultClientSettings);
    }

    private async Task RefreshToken(CancellationToken ct)
    {
        if (_config.AutoRefreshToken && _token.WrapInfo is not null)
        {
            var refreshBuffer = 5;
            var expiry = _token.WrapInfo.CreationTime.AddSeconds(_token.WrapInfo.TimeToLive - refreshBuffer);
            if (DateTimeOffset.UtcNow >= expiry)
            {
                _vaultClient.V1.Auth.ResetVaultToken();
                _token = await _vaultClient.V1.Auth.Token.LookupSelfAsync().WithCancellation(ct);
            }
        }
    }

    private EncryptionKeyType GetEncryptionKeyType(TransitKeyType type) => type switch
    {
        TransitKeyType.aes256_gcm96 => EncryptionKeyType.Aes256Gcm96,
        _ => throw new ArgumentException($"TransitKeyType {type} not supported")
    };

    private async Task<TResult> RetryOnExceptionAsync<TResult, TException>(
            int maxRetryCount,
            TimeSpan delay,
            Func<Task<TResult>> onRetryAsync,
            CancellationToken ct)
            where TException : Exception
    {
        if (maxRetryCount <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxRetryCount));

        var attempts = 0;
        while (true)
        {
            try
            {
                attempts++;
                return await onRetryAsync();
            }
            catch (TException ex)
            {
                if (attempts == maxRetryCount)
                {
                    _logger.LogError($"Reached the maximum number of attempts: {attempts}. Throw exception");
                    throw;
                }

                _logger.LogWarning(
                    $"The exception on attempt {attempts} of {maxRetryCount}. Will retry after sleeping for {delay}. {ex}");

                await Task.Delay(delay, ct);
            }
        }
    }
}

internal static class TaskHelper
{
    public static async Task<TResult> WithCancellation<TResult>(
        this Task<TResult> task,
        CancellationToken ct)
    {
        if (task == await Task.WhenAny(task, Task.Delay(Timeout.Infinite, ct)))
        {
            return await task;
        }
        else
        {
            throw new OperationCanceledException(ct);
        }
    }
}
