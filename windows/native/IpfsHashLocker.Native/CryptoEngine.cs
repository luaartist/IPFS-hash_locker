using System.Security.Cryptography;
using System.Text;

namespace IpfsHashLocker.Native;

public static class CryptoEngine
{
    public static (byte[] Ciphertext, byte[] Nonce, byte[] Tag) EncryptAesGcm(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 256 bits (32 bytes).", nameof(key));

        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return (ciphertext, nonce, tag);
    }

    public static byte[] DecryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag, byte[]? associatedData = null)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 256 bits (32 bytes).", nameof(key));

        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public static byte[] DeriveKeyPbkdf2(string passphrase, byte[] salt, int iterations = 100_000, int keyLength = 32)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passphrase),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            keyLength
        );
    }

    public static string ComputeSha256(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        byte[] hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
