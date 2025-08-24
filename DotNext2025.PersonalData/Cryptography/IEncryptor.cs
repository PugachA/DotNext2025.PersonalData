namespace DotNext2025.PersonalData.Cryptography;
public interface IEncryptor
{
    byte[] Decrypt(ReadOnlySpan<byte> data);
    byte[] Encrypt(ReadOnlySpan<byte> data);
}
