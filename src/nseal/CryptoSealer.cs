namespace NSeal
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using SharpCompress.Archives.Zip;
    using SharpCompress.Compressors.Deflate;

    /// <summary>
    /// Defines the crypto sealer type.
    /// </summary>
    public sealed class CryptoSealer : IDisposable
    {
        private readonly JsonSerializer _serializer = JsonSerializer.Create(CryptoSettings.SerializerSettings);
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
        /// <returns>A <see cref="Task"/> for the async operation.</returns>
        public async Task Encrypt(IEnumerable<EncryptionContent> content, Stream output)
        {
            var metadata = new PackageContainer { Created = DateTimeOffset.Now };

            using var outerZip = ZipArchive.Create();
            outerZip.DeflateCompressionLevel = CompressionLevel.BestCompression;

            var contentStreams = new List<Stream>();
            foreach (var encryptionContent in content)
            {
                using var algo = _algo();

                algo.GenerateKey();
                algo.GenerateIV();
                using var encryptor = algo.CreateEncryptor();
                var (bundle, stream) = await CreateBundle(encryptionContent, encryptor, outerZip, algo).ConfigureAwait(false);

                contentStreams.Add(stream);

                metadata.Bundles.Add(bundle);
            }
            var metadataStream = WriteMetadata(metadata, outerZip);
            contentStreams.Add(metadataStream);

            outerZip.SaveTo(output);

            foreach (var contentStream in contentStreams)
            {
                await contentStream.DisposeAsync().ConfigureAwait(false);
            }
        }

        private Stream WriteMetadata(PackageContainer metadata, ZipArchive outerZip)
        {
            var metadataStream = new MemoryStream();
            using var streamWriter = new StreamWriter(metadataStream, Encoding.UTF8, 4096, true);
            using var jsonWriter = new JsonTextWriter(streamWriter);
            _serializer.Serialize(jsonWriter, metadata, typeof(PackageContainer));
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
            await WriteEncrypted(encryptionContent.Content, encryptor, encryptedStream, cancellationToken).ConfigureAwait(false);

            encryptedStream.Position = 0;

            using var hmac = new HMACSHA256();
#if NETSTANDARD2_1
            var hash = hmac.ComputeHash(encryptedStream);
#else
            var hash = await hmac.ComputeHashAsync(encryptedStream, cancellationToken).ConfigureAwait(false);
#endif
            encryptedStream.Position = 0;

            outerZip.AddEntry(encryptionContentKey, encryptedStream, encryptedStream.Length);
            var bundle = BuildBundle(aes, encryptionContentKey, hash, hmac.Key);
            return (bundle, encryptedStream);
        }

        private Bundle BuildBundle(SymmetricAlgorithm algorithm, string encryptionContentKey, byte[] authCode, byte[] hmacKey)
        {
            return new Bundle
            {
                AssemblyTime = DateTimeOffset.Now,
                ContentLink = encryptionContentKey,
                Cryptography = new Cryptography
                {
                    Algorithm = GetAlgorithm(algorithm.GetType()),
                    BlockSize = algorithm.BlockSize,
                    KeySize = algorithm.KeySize,
                    CipherMode = algorithm.Mode,
                    Padding = algorithm.Padding,
                    InitVector = Convert.ToBase64String(algorithm.IV),
                    EncryptionKey = Convert.ToBase64String(_receiverPublicKey.Encrypt(algorithm.Key, RSAEncryptionPadding.Pkcs1)),
                    AuthCode = Convert.ToBase64String(authCode),
                    AuthKey = Convert.ToBase64String(_receiverPublicKey.Encrypt(hmacKey, RSAEncryptionPadding.Pkcs1))
                }
            };
        }

        private static string GetAlgorithm(Type type)
        {
            if (typeof(Aes).IsAssignableFrom(type))
            {
                return "aes";
            }

            if (typeof(DES).IsAssignableFrom(type))
            {
                return "des";
            }

            if (typeof(TripleDES).IsAssignableFrom(type))
            {
                return "tripledes";
            }

            if (typeof(RC2).IsAssignableFrom(type))
            {
                return "rc2";
            }

            throw new ArgumentException("Unknown or unsupported algorithm type", nameof(type));
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
            int read;
            while ((read = await content.ReadAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                await cs.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            await cs.FlushAsync(cancellationToken).ConfigureAwait(false);
#if NETSTANDARD2_1
            cs.FlushFinalBlock();
#else
            await cs.FlushFinalBlockAsync(cancellationToken).ConfigureAwait(false);
#endif
            cs.Close();
            arrayPool.Return(buffer);
        }

        public void Dispose()
        {
            _receiverPublicKey.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}