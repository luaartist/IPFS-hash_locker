using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;

namespace IpfsHashLocker.Native;

public static class MemoryMappedTensorHasher
{
    public static (string Sha256, long FileSize) ComputeTensorHashMmap(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
            throw new FileNotFoundException($"File not found: {filePath}");

        long length = fileInfo.Length;
        if (length == 0)
            return (CryptoEngine.ComputeSha256(Array.Empty<byte>()), 0);

        using var mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        using var stream = mmf.CreateViewStream(0, length, MemoryMappedFileAccess.Read);

        byte[] hash = SHA256.HashData(stream);
        return (Convert.ToHexString(hash).ToLowerInvariant(), length);
    }
}
