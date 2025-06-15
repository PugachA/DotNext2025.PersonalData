using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNext2025.PersonalData.Core;
public interface IIntegrationMessage;

public interface IIntegrationMessage<TKey> 
    : IIntegrationMessage
{
    public TKey GetKey();
}

