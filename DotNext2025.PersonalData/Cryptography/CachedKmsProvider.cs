using System.Collections.Concurrent;

namespace DotNext2025.PersonalData.Cryptography;
public class CachedKmsProvider(
    IKmsProvider kmsProvider, TimeSpan latestKeyCacheExpiration) : IKmsProvider
{
    private readonly ConcurrentDictionary<
        (string keyName, string keyVersion), Lazy<Task<EncryptionKey>>> _cache = new();

    private readonly Lock _latestLock = new();
    private Lazy<Task<EncryptionKey>>? latestKeyCache = new();
    private DateTime latestCacheDateTime = DateTime.MinValue;

    public Task<EncryptionKey> GetEncryptionKey(string keyName, string keyVersion, CancellationToken ct = default)
    {
        var lazyKey = _cache.GetOrAdd(
            (keyName, keyVersion),
            k => new Lazy<Task<EncryptionKey>>(() => kmsProvider.GetEncryptionKey(k.keyName, k.keyVersion, ct)));

        return lazyKey.Value;
    }

    public Task<EncryptionKey> GetLatestEncryptionKey(string keyName, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        if (latestKeyCache is not null && now - latestCacheDateTime < latestKeyCacheExpiration)
            return latestKeyCache.Value;

        var key = new Lazy<Task<EncryptionKey>>(() => kmsProvider.GetLatestEncryptionKey(keyName, ct));

        lock (_latestLock)
        {
            latestKeyCache = key;
            latestCacheDateTime = now;
            return key.Value;
        }
    }
}
