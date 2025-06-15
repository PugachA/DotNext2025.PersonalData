using System.Reflection;
using System.Text.Json;
using Confluent.Kafka;
using DotNext2025.PersonalData.Core;
using DotNext2025.PersonalData.Cryptography;

namespace DotNext2025.PersonalData.Kafka;
public class EncryptedKafkaJsonSerializer<T>(IKmsProvider kmsProvider, JsonSerializerOptions? options = null) 
    : BaseEncryptedKafkaJsonSerializer<T>(kmsProvider, options), IAsyncSerializer<T> where T : IIntegrationMessage
{
    private readonly EncryptionAlgorithm _algorithm = IntegrationAttr.EncryptionAlgorithm;
    //Работаем только в рамках одного mountPoint
    private readonly string _keyName = $"{typeof(T).Name}-{IntegrationAttr.EncryptionAlgorithm}";

    private readonly Lock _cacheLock = new();
    private (string Version, JsonSerializerOptions Options)? _cachedOptions;

    public async Task<byte[]> SerializeAsync(T? data, SerializationContext context)
    {
        var key = await KmsProvider.GetLatestEncryptionKey(_keyName);

        AddHeader(context.Headers, AlgorithmHeader, _algorithm.ToString());
        AddHeader(context.Headers, KeyNameHeader, key.Name);
        AddHeader(context.Headers, KeyVersionHeader, key.Version);

        var options = GetOptions(key);
        return JsonSerializer.SerializeToUtf8Bytes(data, options);
    }

    private JsonSerializerOptions GetOptions(EncryptionKey key)
    {
        if (_cachedOptions?.Version == key.Version)
            return _cachedOptions.Value.Options;

        JsonSerializerOptions options;
        lock (_cacheLock)
        {
            if (_cachedOptions?.Version == key.Version)
                options = _cachedOptions.Value.Options;
            else
            {
                options = CreateJsonOptions(key, _algorithm, BaseOptions);
                _cachedOptions = (key.Version, options);
            }
        }

        return options;
    }
}