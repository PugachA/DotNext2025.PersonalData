using Confluent.Kafka;
using DotNext2025.PersonalData.Core;
using DotNext2025.PersonalData.Cryptography;
using System.Collections.Concurrent;
using System.Text.Json;

namespace DotNext2025.PersonalData.Kafka;
public class EncryptedKafkaJsonDeserializer<T>(IKmsProvider kmsProvider, JsonSerializerOptions? options = null)
    : BaseEncryptedKafkaJsonSerializer<T>(kmsProvider, options), IAsyncDeserializer<T?> where T : IIntegrationMessage
{
    private readonly ConcurrentDictionary<CacheKey, JsonSerializerOptions> _encryptionOptionsCache = new();

    public async Task<T?> DeserializeAsync(ReadOnlyMemory<byte> data, bool isNull, SerializationContext context)
    {
        if (isNull) 
            return default;

        if (context.Headers is null)
            throw new ArgumentException("Headers is empty");

        var algorithm = Enum.Parse<EncryptionAlgorithm>(GetHeader(context.Headers, AlgorithmHeader));
        var keyName = GetHeader(context.Headers, KeyNameHeader);
        var keyVersion = GetHeader(context.Headers, KeyVersionHeader);
        var key = await KmsProvider.GetEncryptionKey(keyName, keyVersion);

        var cacheKey = new CacheKey(keyName, keyVersion, algorithm);
        var options = _encryptionOptionsCache.GetOrAdd(cacheKey, _ => CreateJsonOptions(key, algorithm, BaseOptions));
        return JsonSerializer.Deserialize<T>(data.Span, options);
    }

    private readonly record struct CacheKey(string Name, string Version, EncryptionAlgorithm Type);
}
