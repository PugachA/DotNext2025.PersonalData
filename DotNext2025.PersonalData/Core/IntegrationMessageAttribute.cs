namespace DotNext2025.PersonalData.Core;

[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
public class EncryptedAttribute : Attribute
{ }

[AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
public class IntegrationMessageAttribute : Attribute
{
    public EncryptionAlgorithm EncryptionAlgorithm { get; set; }

    public IntegrationMessageAttribute(
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.None)
    {
        EncryptionAlgorithm = algorithm;
    }
}

