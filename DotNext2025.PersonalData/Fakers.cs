using Bogus;
using DotNext2025.PersonalData.Core;

namespace DotNext2025.PersonalData;
public static class Fakers
{
    public static Faker<Customer> Customer => new Faker<Customer>()
        .RuleFor(o => o.CustomerId, f => Guid.NewGuid())
        .RuleFor(o => o.Subscription, f => f.PickRandom(new[] { "None", "Standard", "Pro", "Premium" }))
        .RuleFor(o => o.Email, f => f.Internet.Email())
        .RuleFor(o => o.SecretToken, f => Guid.NewGuid())
        .RuleFor(o => o.RegistrationDate, f => DateTime.UtcNow)
        .RuleFor(o => o.Address, f => new Address
        {
            City = f.Address.City(),
            Street = f.Address.StreetName()
        })
        .RuleFor(o => o.Passport, f => new Passport
        {
            Number = Guid.NewGuid().ToString()
        });
}
