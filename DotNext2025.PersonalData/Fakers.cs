using Bogus;
using DotNext2025.PersonalData.Core;

namespace DotNext2025.PersonalData;
public static class Fakers
{
    public static Faker<Order> Order => new Faker<Order>()
        .RuleFor(o => o.OrderId, f => Guid.NewGuid())
        .RuleFor(o => o.PaymentMethod, f => f.PickRandom(new[] { "Mir" }))
        .RuleFor(o => o.Email, f => f.Internet.Email())
        .RuleFor(o => o.Phone, f => f.Phone.PhoneNumber())
        .RuleFor(o => o.OrderDate, f => DateTime.UtcNow)
        .RuleFor(o => o.Address, f => new Address
        {
            City = f.Address.City(),
            Street = f.Address.StreetName()
        })
        .RuleFor(o => o.Items, f => OrderItem.Generate(1))
        .RuleFor(o => o.Currency, f => "RUB")
        .RuleFor(o => o.TotalAmount, (f, o) => o.Items.Select(e => e.PricePerUnit * e.Quantity).Sum());

    public static Faker<OrderItem> OrderItem => new Faker<OrderItem>()
        .RuleFor(o => o.SKU, f => Guid.NewGuid().ToString())
        .RuleFor(o => o.Name, f => f.Commerce.ProductName())
        .RuleFor(o => o.Quantity, f => f.Random.Number(1, 3))
        .RuleFor(o => o.PricePerUnit, f => f.Finance.Amount());
}
