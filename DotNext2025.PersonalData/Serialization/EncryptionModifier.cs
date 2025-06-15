using System.Collections.Concurrent;
using System.Text.Json.Serialization.Metadata;
using System.Text.Json.Serialization;
using DotNext2025.PersonalData.Cryptography;
using System.Reflection;
using DotNext2025.PersonalData.Core;

namespace DotNext2025.PersonalData.Serialization;
public class EncryptionModifier(IEncryptor encryptor)
{
    private readonly ConcurrentDictionary<Type, JsonConverter> _cache = new();

    public void Modify(JsonTypeInfo typeInfo)
    {
        if (typeInfo.Kind == JsonTypeInfoKind.Object)
        {
            foreach (var jsonProp in typeInfo.Properties)
            {
                var isEncrypted = jsonProp.AttributeProvider?
                    .GetCustomAttributes(true)
                    .Any(attr => attr is EncryptedAttribute) is true;

                if (isEncrypted)
                    jsonProp.CustomConverter = CreateConverter(jsonProp.PropertyType);
            }
        }
    }

    private JsonConverter CreateConverter(Type type) => _cache.GetOrAdd(type,
        (k) => (JsonConverter)Activator.CreateInstance(
            typeof(EncryptionConverter<>).MakeGenericType(k),
            BindingFlags.Instance | BindingFlags.Public,
            binder: null, args: [encryptor], culture: null)!);
}
