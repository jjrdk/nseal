﻿using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;

namespace NSeal
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;
    using SharpCompress.Archives.Zip;
    using SharpCompress.Compressors.Deflate;

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
        }

        /// <summary>
        /// Encrypts the passed content into the passed stream.
        /// </summary>
        /// <param name="content">The content to encrypt.</param>
        /// <param name="output">The <see cref="Stream"/> to write output to.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the async operation.</param>
        /// <returns>A <see cref="Task"/> for the async operation.</returns>
        [RequiresUnreferencedCode("Serializes to stream")]
#if NET8_0_OR_GREATER
        [RequiresDynamicCode("Serializes to stream")]
#endif
        public async Task Encrypt(
            IEnumerable<EncryptionContent> content,
            Stream output,
            CancellationToken cancellationToken = default)
        {
            var metadata = new PackageContainer { Created = DateTimeOffset.Now };

            using var outerZip = ZipArchive.Create();
            outerZip.DeflateCompressionLevel = CompressionLevel.BestCompression;

            var contentStreams = new List<Stream>();
            using var algo = _algo();

            algo.GenerateKey();
            algo.GenerateIV();
            using var encryptor = algo.CreateEncryptor();
            foreach (var encryptionContent in content)
            {
                var (bundle, stream) =
                    await CreateBundle(encryptionContent, encryptor, outerZip, algo, cancellationToken)
                        .ConfigureAwait(false);

                contentStreams.Add(stream);

                metadata.Bundles.Add(bundle);
            }

            var metadataStream = await WriteMetadata(metadata, outerZip, cancellationToken).ConfigureAwait(false);
            contentStreams.Add(metadataStream);

            outerZip.SaveTo(output);

            await Task.WhenAll(contentStreams.Select(s => s.DisposeAsync().AsTask()));
        }

        [RequiresUnreferencedCode("Serializes to stream")]
#if NET8_0_OR_GREATER
        [RequiresDynamicCode("Serializes to stream")]
#endif
        private static async Task<Stream> WriteMetadata(
            PackageContainer metadata,
            ZipArchive outerZip,
            CancellationToken cancellationToken)
        {
            var metadataStream = new MemoryStream();
            await JsonSerializer.SerializeAsync(metadataStream, metadata,
                CryptoSettings.SerializerSettings, cancellationToken).ConfigureAwait(false);
            outerZip.AddEntry("metadata.json", metadataStream, metadataStream.Length);

            return metadataStream;
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

        private async Task<(Bundle bundle, Stream stream)> CreateBundle(
            EncryptionContent encryptionContent,
            ICryptoTransform encryptor,
            ZipArchive outerZip,
            SymmetricAlgorithm aes,
            CancellationToken cancellationToken = default)
        {
            var encryptionContentKey = encryptionContent.Key + ".enc";

            var encryptedStream = new MemoryStream();
            await WriteEncrypted(encryptionContent.Content, encryptor, encryptedStream, cancellationToken)
                .ConfigureAwait(false);

            encryptedStream.Position = 0;

            using var hmac = new HMACSHA256();
            var hash = await hmac.ComputeHashAsync(encryptedStream, cancellationToken).ConfigureAwait(false);
            encryptedStream.Position = 0;

            outerZip.AddEntry(encryptionContentKey, encryptedStream, encryptedStream.Length);
            var bundle = BuildBundle(aes, encryptionContentKey, hash, hmac.Key);
            return (bundle, encryptedStream);
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
                        Convert.ToBase64String(_receiverPublicKey.Encrypt(algorithm.Key, RSAEncryptionPadding.Pkcs1)),
                    AuthCode = Convert.ToBase64String(authCode),
                    AuthKey = Convert.ToBase64String(_receiverPublicKey.Encrypt(hmacKey, RSAEncryptionPadding.Pkcs1))
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

        private static async Task WriteEncrypted(
            Stream content,
            ICryptoTransform encryptor,
            Stream encryptedStream,
            CancellationToken cancellationToken = default)
        {
            const int length = 4096;
            var arrayPool = ArrayPool<byte>.Shared;
            var buffer = arrayPool.Rent(length);
            var cs = new CryptoStream(encryptedStream, encryptor, CryptoStreamMode.Write, true);
            await using var _ = cs.ConfigureAwait(false);
            await content.CopyToAsync(cs, length, cancellationToken).ConfigureAwait(false);

            await cs.FlushAsync(cancellationToken).ConfigureAwait(false);
            await cs.FlushFinalBlockAsync(cancellationToken).ConfigureAwait(false);
            cs.Close();
            arrayPool.Return(buffer);
        }

        public void Dispose()
        {
            _receiverPublicKey.Dispose();
        }
    }
}
