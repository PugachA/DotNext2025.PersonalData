#pragma warning disable CS8618

namespace DotNext2025.PersonalData.Core;

[IntegrationMessage(EncryptionAlgorithm.Aes256GcmIv96Tag128)]
public class Customer : IIntegrationMessage<Guid>
{
    public Guid CustomerId { get; set; }

    public string Subscription { get; set; }

    [Encrypted]
    public string Email { get; set; }

    [Encrypted]
    public Guid SecretToken { get; set; }

    [Encrypted]
    public Passport Passport { get; set; }

    public Address Address { get; set; }

    public DateTime RegistrationDate { get; set; }

    public Guid GetKey() => CustomerId;
}

public class Address
{
    public string City { get; set; }

    [Encrypted]
    public string Street { get; set; }
}

public class Passport
{
    public string Number { get; set; }
}
