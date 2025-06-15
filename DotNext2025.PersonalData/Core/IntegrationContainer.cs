#pragma warning disable CS8618

namespace DotNext2025.PersonalData.Core;

//Можно через контейнер или через хедеры
public class IntegrationContainer<TKey, TMessage> where TMessage : IIntegrationMessage<TKey>
{
    public TMessage Message { get; set; }
    public Metadata? Metadata { get; set; }
}

public class Metadata
{
    public EncryptionParameters? EncryptionParameters { get; set; }
}

public record EncryptionParameters(EncryptionAlgorithm Algorithm, string KeyName, string KeyVersion);

