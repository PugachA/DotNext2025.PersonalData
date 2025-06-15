using System.Security.Cryptography;

namespace DotNext2025.PersonalData.Cryptography;
public class AesGcmEncryptor : IEncryptor, IDisposable
{
    private readonly AesGcm _aesGcm;
    private readonly byte _ivSize;
    private readonly byte _tagSize;

    public AesGcmEncryptor(byte[] key, byte ivByteSize = 12, byte tagByteSize = 16)
    {
        if (tagByteSize < AesGcm.TagByteSizes.MinSize || tagByteSize > AesGcm.TagByteSizes.MaxSize)
            throw new ArgumentException($"Invalid {nameof(tagByteSize)}={tagByteSize}. MinSize={AesGcm.TagByteSizes.MinSize} MaxSize={AesGcm.TagByteSizes.MaxSize}");
        _tagSize = tagByteSize;

        if (ivByteSize < AesGcm.NonceByteSizes.MinSize || ivByteSize > AesGcm.NonceByteSizes.MaxSize)
            throw new ArgumentException($"Invalid {nameof(ivByteSize)}={ivByteSize}. MinSize={AesGcm.NonceByteSizes.MinSize} MaxSize={AesGcm.NonceByteSizes.MaxSize}");
        _ivSize = ivByteSize;

        _aesGcm = new AesGcm(key, tagByteSize);
    }

    public byte[] Encrypt(ReadOnlySpan<byte> data)
    {
        var cipherSize = data.Length;
        var encryptedDataLength = 1 + _ivSize + 1 + _tagSize + cipherSize;
        Span<byte> encryptedData = new byte[encryptedDataLength];

        encryptedData[0] = _ivSize;
        encryptedData[1 + _ivSize] = _tagSize;

        var nonce = encryptedData.Slice(1, _ivSize);
        var tag = encryptedData.Slice(1 + _ivSize + 1, _tagSize);
        var cipherBytes = encryptedData.Slice(1 + _ivSize + 1 + _tagSize, cipherSize);

        RandomNumberGenerator.Fill(nonce);
        _aesGcm.Encrypt(nonce, data, cipherBytes, tag);
        return encryptedData.ToArray();
    }

    public byte[] Decrypt(ReadOnlySpan<byte> encryptedData)
    {
        var nonceSize = encryptedData[0];
        var tagSize = encryptedData[1 + nonceSize];
        var cipherSize = encryptedData.Length - 1 - nonceSize - 1 - tagSize;

        var nonce = encryptedData.Slice(1, nonceSize);
        var tag = encryptedData.Slice(1 + nonceSize + 1, tagSize);
        var cipherBytes = encryptedData.Slice(1 + nonceSize + 1 + tagSize, cipherSize);

        var plainBytes = new byte[cipherSize];
        _aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);
        return plainBytes;
    }

    public void Dispose()
    {
        _aesGcm.Dispose();
    }
}
