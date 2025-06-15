using DotNext2025.PersonalData.Core;

namespace DotNext2025.PersonalData.Db;
internal interface IDbEncryptionProvider
{
    EncryptionParameters EncryptionParameters { get; }
    byte[] Encrypt(ReadOnlySpan<char> data);
}
