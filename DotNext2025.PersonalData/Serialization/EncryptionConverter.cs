using System.Text.Json.Serialization;
using System.Text.Json;
using DotNext2025.PersonalData.Cryptography;

namespace DotNext2025.PersonalData.Serialization;
internal class EncryptionConverter<T>(IEncryptor encryptor) : JsonConverter<T>
{
    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(value, options);
        var encrypted = encryptor.Encrypt(jsonBytes);
        writer.WriteBase64StringValue(encrypted);
    }

    public override T? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var bytes = reader.GetBytesFromBase64();
        if (bytes is null)
            return default;

        var jsonBytes = encryptor.Decrypt(bytes);
        return JsonSerializer.Deserialize<T>(jsonBytes, options);
    }
}
