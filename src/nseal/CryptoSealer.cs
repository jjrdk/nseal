using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Text.Json;

namespace NSeal;

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Defines the crypto sealer type.
/// </summary>
public sealed class CryptoSealer : IDisposable
{
    private readonly RSA _receiverPublicKey;
    private readonly Func<SymmetricAlgorithm> _algo;

    /// <summary>
    /// Initializes a new instance of the <see cref="CryptoSealer"/> sealed class.
    /// </summary>
    /// <param name="receiverPublicKey">The <see cref="RSA">public key</see> of the intended recipient</param>
    /// <param name="algo">The <see cref="SymmetricAlgorithm"/> to apply for encryption.</param>
    public CryptoSealer(RSA receiverPublicKey, Func<SymmetricAlgorithm>? algo = null)
    {
        _receiverPublicKey = receiverPublicKey;
        _algo = algo ?? CreateAes;
        using var algorithm = _algo();
        if (algorithm.Padding is PaddingMode.Zeros or PaddingMode.None)
        {
            throw new ArgumentException($"{algorithm.Padding} is not secure for encryption", nameof(algo));
        }
    }

    /// <summary>
    /// Encrypts the passed content into the passed stream.
    /// </summary>
    /// <param name="content">The content to encrypt.</param>
    /// <param name="output">The <see cref="Stream"/> to write output to.</param>
    /// <param name="leaveOpen">Toggles whether to leave the output stream open.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the async operation.</param>
    /// <returns>A <see cref="Task"/> for the async operation.</returns>
    [RequiresUnreferencedCode("Serializes to stream")]
    [RequiresDynamicCode("Serializes to stream")]
    public async Task Encrypt(
        IEnumerable<EncryptionContent> content,
        Stream output,
        bool leaveOpen = false,
        CancellationToken cancellationToken = default)
    {
        var metadata = new PackageContainer { Created = DateTimeOffset.Now };

        using var outerZip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen);
        using var algo = _algo();

        algo.GenerateKey();
        algo.GenerateIV();
        using var encryptor = algo.CreateEncryptor();
        foreach (var encryptionContent in content)
        {
            var bundle =
                await CreateBundle(encryptionContent, encryptor, outerZip, algo, cancellationToken)
                    .ConfigureAwait(false);

            metadata.Bundles.Add(bundle);
        }

        await WriteMetadata(metadata, outerZip, cancellationToken).ConfigureAwait(false);
    }

    [RequiresUnreferencedCode("Serializes to stream")]
    [RequiresDynamicCode("Serializes to stream")]
    private static async Task WriteMetadata(
        PackageContainer metadata,
        ZipArchive outerZip,
        CancellationToken cancellationToken)
    {
        var metadataEntry = outerZip.CreateEntry("metadata.json", CompressionLevel.Optimal);
        await using var entryStream = metadataEntry.Open();
        await JsonSerializer.SerializeAsync(entryStream, metadata,
            CryptoSettings.SerializerSettings, cancellationToken).ConfigureAwait(false);
        await entryStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static SymmetricAlgorithm CreateAes()
    {
        var algo = Aes.Create();
        algo.BlockSize = 128;
        algo.KeySize = 256;
        algo.Mode = CipherMode.CBC;
        algo.Padding = PaddingMode.PKCS7;
        return algo;
    }

    private async Task<Bundle> CreateBundle(
        EncryptionContent encryptionContent,
        ICryptoTransform encryptor,
        ZipArchive outerZip,
        SymmetricAlgorithm algorithm,
        CancellationToken cancellationToken = default)
    {
        var encryptionContentKey = $"{encryptionContent.Key}.enc";
        var encryptionContentEntry = outerZip.CreateEntry(encryptionContentKey, CompressionLevel.Optimal);
        await using var entryStream = encryptionContentEntry.Open();
        var (key, hash) = await WriteEncrypted(encryptionContent.Content, encryptor, entryStream, cancellationToken)
            .ConfigureAwait(false);

        var bundle = BuildBundle(algorithm, encryptionContentKey, hash, key);
        return bundle;
    }

    private Bundle BuildBundle(
        SymmetricAlgorithm algorithm,
        string encryptionContentKey,
        ReadOnlySpan<byte> authCode,
        byte[] hmacKey)
    {
        return new Bundle
        {
            AssemblyTime = DateTimeOffset.Now,
            ContentLink = encryptionContentKey,
            Cryptography = new Cryptography
            {
                Algorithm = GetAlgorithm(algorithm),
                BlockSize = algorithm.BlockSize,
                KeySize = algorithm.KeySize,
                CipherMode = algorithm.Mode,
                Padding = algorithm.Padding,
                InitVector = Convert.ToBase64String(algorithm.IV),
                EncryptionKey =
                    Convert.ToBase64String(_receiverPublicKey.Encrypt(algorithm.Key,
                        RSAEncryptionPadding.OaepSHA256)),
                AuthCode = Convert.ToBase64String(authCode),
                AuthKey = Convert.ToBase64String(_receiverPublicKey.Encrypt(hmacKey,
                    RSAEncryptionPadding.OaepSHA256))
            }
        };
    }

    private static string GetAlgorithm(SymmetricAlgorithm type)
    {
        return type switch
        {
            Aes => "aes",
            DES => "des",
            TripleDES => "tripledes",
            RC2 => "rc2",
            _ => throw new ArgumentException("Unknown or unsupported algorithm type", nameof(type))
        };
    }

    private static async Task<(byte[] key, byte[] hash)> WriteEncrypted(
        Stream content,
        ICryptoTransform encryptor,
        Stream encryptedStream,
        CancellationToken cancellationToken = default)
    {
        const int length = 4096;
        var cs = new CryptoStream(encryptedStream, encryptor, CryptoStreamMode.Write, true);
        await using var _ = cs.ConfigureAwait(false);
        await using var hasher = new HashingStream(cs);
        await content.CopyToAsync(hasher, length, cancellationToken).ConfigureAwait(false);
        await hasher.FlushAsync(cancellationToken).ConfigureAwait(false);
        await cs.FlushFinalBlockAsync(cancellationToken).ConfigureAwait(false);
        return hasher.GetHash();
    }

    public void Dispose()
    {
        _receiverPublicKey.Dispose();
    }
}
