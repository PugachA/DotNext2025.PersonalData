using DotNext2025.PersonalData.Core;
using DotNext2025.PersonalData.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNext2025.PersonalData.Db;
internal interface IDbProviderFactory
{
    public IDbEncryptionProvider GetEncryptor(string keyName, EncryptionAlgorithm algorithm);
    public IDbDecryptionProvider GetDecryptor();
}
