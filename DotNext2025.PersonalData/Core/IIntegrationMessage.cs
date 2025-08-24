namespace DotNext2025.PersonalData.Core;
public interface IIntegrationMessage;

public interface IIntegrationMessage<TKey> 
    : IIntegrationMessage
{
    public TKey GetKey();
}

