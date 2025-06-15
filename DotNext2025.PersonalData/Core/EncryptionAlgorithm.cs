using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNext2025.PersonalData.Core;
public enum EncryptionAlgorithm : byte
{
    None = 0,
    Aes256GcmIv96Tag128 = 1
}
