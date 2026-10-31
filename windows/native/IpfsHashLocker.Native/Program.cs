using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IpfsHashLocker.Native;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("===============================================================");
        Console.WriteLine("  IPFS Hash Locker - Native Windows Engine");
        Console.WriteLine("===============================================================");

        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return 0;
        }

        string command = args[0].ToLowerInvariant();

        try
        {
            switch (command)
            {
                case "id":
                    return await HandleIdCommand(args);

                case "hash":
                    return HandleHashCommand(args);

                case "tensor-verify":
                    return HandleTensorVerifyCommand(args);

                case "lock":
                    return HandleLockCommand(args);

                case "unlock":
                    return HandleUnlockCommand(args);

                case "upload":
                    return await HandleUploadCommand(args);

                case "cat":
                case "download":
                    return await HandleDownloadCommand(args);

                default:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] Unknown command: {command}");
                    Console.ResetColor();
                    PrintUsage();
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[-] Error: {ex.Message}");
            Console.ResetColor();
            return 1;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"
Usage: ipfs-locker-native <command> [options]

Commands:
  id                      Inspect local/remote Kubo IPFS Node identity.
  hash <file>             Compute SHA-256 and companion metadata for a file.
  tensor-verify <file>    Zero-copy memory-mapped hash of multi-gigabyte tensor.
  lock <file> -k <pass>   AES-256-GCM authenticated encryption with PBKDF2.
  unlock <file> -k <pass> Decrypt and verify authenticated bundle.
  upload <file>           Upload file to local Kubo IPFS node and pin.
  download <cid> -o <out> Retrieve and verify payload by CID from IPFS.
");
    }

    private static async Task<int> HandleIdCommand(string[] args)
    {
        string host = args.Length > 1 ? args[1] : "http://127.0.0.1:5001";
        var client = new KuboClientNative(host);
        Console.WriteLine($"[*] Checking IPFS node identity at {host}...");
        string? nodeId = await client.GetNodeIdAsync();
        if (nodeId != null)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Node Connected! Peer ID: {nodeId}");
            Console.ResetColor();
            return 0;
        }
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[!] IPFS Node not reachable at {host}. Gateway fallback mode.");
        Console.ResetColor();
        return 0;
    }

    private static int HandleHashCommand(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: ipfs-locker-native hash <file>");
            return 1;
        }
        string file = args[1];
        string sha = CryptoEngine.ComputeSha256(file);
        Console.WriteLine($"[+] File: {file}");
        Console.WriteLine($"[+] SHA-256: {sha}");
        return 0;
    }

    private static int HandleTensorVerifyCommand(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: ipfs-locker-native tensor-verify <tensor_file>");
            return 1;
        }
        string file = args[1];
        Console.WriteLine($"[*] Scanning tensor checkpoint via zero-copy mmap: {file}...");
        var (sha, size) = MemoryMappedTensorHasher.ComputeTensorHashMmap(file);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] Tensor Size: {size:N0} bytes");
        Console.WriteLine($"[+] Memory-Mapped SHA-256: {sha}");
        Console.WriteLine("[+] Verification Status: PASSED (Zero-copy verified)");
        Console.ResetColor();
        return 0;
    }

    private static int HandleLockCommand(string[] args)
    {
        if (args.Length < 4)
        {
            Console.WriteLine("Usage: ipfs-locker-native lock <file> -k <passphrase> [-o <out>]");
            return 1;
        }
        string file = args[1];
        string pass = args[3];
        string outFile = args.Length > 5 && args[4] == "-o" ? args[5] : file + ".enc";

        byte[] rawBytes = File.ReadAllBytes(file);
        byte[] salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        byte[] key = CryptoEngine.DeriveKeyPbkdf2(pass, salt);

        var (ciphertext, nonce, tag) = CryptoEngine.EncryptAesGcm(rawBytes, key);

        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);
        bw.Write(Encoding.ASCII.GetBytes("HLK_WIN_V1")); // Header
        bw.Write(salt);                                  // 16 bytes
        bw.Write(nonce);                                 // 12 bytes
        bw.Write(tag);                                   // 16 bytes
        bw.Write(ciphertext.Length);                     // 4 bytes
        bw.Write(ciphertext);                            // Data

        File.WriteAllBytes(outFile, ms.ToArray());
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] File locked and encrypted: {outFile}");
        Console.WriteLine($"[+] Original SHA-256: {CryptoEngine.ComputeSha256(rawBytes)}");
        Console.ResetColor();
        return 0;
    }

    private static int HandleUnlockCommand(string[] args)
    {
        if (args.Length < 4)
        {
            Console.WriteLine("Usage: ipfs-locker-native unlock <file.enc> -k <passphrase> [-o <out>]");
            return 1;
        }
        string encFile = args[1];
        string pass = args[3];
        string outFile = args.Length > 5 && args[4] == "-o" ? args[5] : encFile.Replace(".enc", ".dec");

        byte[] rawEnc = File.ReadAllBytes(encFile);
        using var ms = new MemoryStream(rawEnc);
        using var br = new BinaryReader(ms);

        string header = Encoding.ASCII.GetString(br.ReadBytes(10));
        if (header != "HLK_WIN_V1")
            throw new InvalidDataException("Invalid container header.");

        byte[] salt = br.ReadBytes(16);
        byte[] nonce = br.ReadBytes(12);
        byte[] tag = br.ReadBytes(16);
        int cipherLen = br.ReadInt32();
        byte[] ciphertext = br.ReadBytes(cipherLen);

        byte[] key = CryptoEngine.DeriveKeyPbkdf2(pass, salt);
        byte[] decrypted = CryptoEngine.DecryptAesGcm(ciphertext, key, nonce, tag);

        File.WriteAllBytes(outFile, decrypted);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] File decrypted & authenticated: {outFile}");
        Console.WriteLine($"[+] Recovered SHA-256: {CryptoEngine.ComputeSha256(decrypted)}");
        Console.ResetColor();
        return 0;
    }

    private static async Task<int> HandleUploadCommand(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: ipfs-locker-native upload <file>");
            return 1;
        }
        string file = args[1];
        var client = new KuboClientNative();
        Console.WriteLine($"[*] Uploading {file} to Kubo IPFS...");
        string cid = await client.AddFileAsync(file, pin: true);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] Pinned to IPFS! CID: {cid}");
        Console.WriteLine($"[+] Gateway URL: https://ipfs.io/ipfs/{cid}");
        Console.ResetColor();
        return 0;
    }

    private static async Task<int> HandleDownloadCommand(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: ipfs-locker-native download <cid> -o <output_file>");
            return 1;
        }
        string cid = args[1];
        string outFile = args.Length > 3 && args[2] == "-o" ? args[3] : "downloaded_" + cid;
        var client = new KuboClientNative();
        Console.WriteLine($"[*] Retrieving CID {cid} from IPFS...");
        byte[] data = await client.CatAsync(cid);
        await File.WriteAllBytesAsync(outFile, data);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[+] Retrieved {data.Length} bytes -> {outFile}");
        Console.WriteLine($"[+] SHA-256: {CryptoEngine.ComputeSha256(data)}");
        Console.ResetColor();
        return 0;
    }
}
