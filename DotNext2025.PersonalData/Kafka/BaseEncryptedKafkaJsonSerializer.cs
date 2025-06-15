using Confluent.Kafka;
using DotNext2025.PersonalData.Core;
using DotNext2025.PersonalData.Cryptography;
using DotNext2025.PersonalData.Serialization;
using System.Text;
using System.Text.Json.Serialization.Metadata;
using System.Text.Json;
using System.Reflection;

namespace DotNext2025.PersonalData.Kafka;
public abstract class BaseEncryptedKafkaJsonSerializer<T> where T : IIntegrationMessage
{
    protected static readonly IntegrationMessageAttribute IntegrationAttr 
        = typeof(T).GetCustomAttribute<IntegrationMessageAttribute>()
        ?? throw new ArgumentException($"Type {typeof(T).Name} must have {nameof(IntegrationMessageAttribute)}");

    protected const string AlgorithmHeader = "x-encryption-algorithm";
    protected const string KeyNameHeader = "x-encryption-keyname";
    protected const string KeyVersionHeader = "x-encryption-keyversion";

    protected readonly IKmsProvider KmsProvider;
    protected readonly JsonSerializerOptions? BaseOptions;

    protected BaseEncryptedKafkaJsonSerializer(IKmsProvider kmsProvider, JsonSerializerOptions? options = null)
    {
        KmsProvider = kmsProvider;
        BaseOptions = options;

        if (IntegrationAttr.EncryptionAlgorithm == EncryptionAlgorithm.None)
            throw new ArgumentException($"{nameof(EncryptionAlgorithm)}={EncryptionAlgorithm.None} not supported");
    }

    protected static JsonSerializerOptions CreateJsonOptions(
        EncryptionKey key, EncryptionAlgorithm algorithm, JsonSerializerOptions? baseOptions)
    {
        var encryptor = EncryptorFactory.CreateEncryptor(key, algorithm);
        var modifier = new EncryptionModifier(encryptor);
        var encOptions = baseOptions is null ? new JsonSerializerOptions() : new(baseOptions);
        encOptions.TypeInfoResolver = encOptions.TypeInfoResolver is null ?
            new DefaultJsonTypeInfoResolver().WithAddedModifier(modifier.Modify) :
            encOptions.TypeInfoResolver.WithAddedModifier(modifier.Modify);

        return encOptions;
    }

    protected static string GetHeader(Headers headers, string key) => Encoding.UTF8.GetString(headers.GetLastBytes(key));
    protected static void AddHeader(Headers headers, string key, string value) => headers.Add(key, Encoding.UTF8.GetBytes(value));
}