#pragma warning disable CS8618

namespace DotNext2025.PersonalData.Core;

[IntegrationMessage(EncryptionAlgorithm.Aes256GcmIv96Tag128)]
public class Order : IIntegrationMessage<Guid>
{
    public Guid OrderId { get; set; }

    // 🔐 Прямые персональные данные
    [Encrypted]
    public string Email { get; set; }
    [Encrypted]
    public string Phone { get; set; }

    // 🔒 Косвенные персональные данные
    [Encrypted]
    public DateTime OrderDate { get; set; }
    [Encrypted]
    public string PaymentMethod { get; set; }
    public Address Address { get; set; }

    // ✅ Не персональные данные
    public List<OrderItem> Items { get; set; }
    public decimal TotalAmount { get; set; }
    public string Currency { get; set; }

    public Guid GetKey() => OrderId;
}

public class Address
{
    public string City { get; set; }

    [Encrypted]
    public string Street { get; set; }
}

public class OrderItem
{
    public string SKU { get; set; }
    public string Name { get; set; }
    public int Quantity { get; set; }
    public decimal PricePerUnit { get; set; }
}