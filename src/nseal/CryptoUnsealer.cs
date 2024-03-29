﻿using System.Diagnostics.CodeAnalysis;

namespace NSeal
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using SharpCompress.Archives.Zip;

    /// <summary>
    /// Defines the crypto unsealer type.
    /// </summary>
    public sealed class CryptoUnsealer : IDisposable
    {
        private readonly RSA _privateKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptoUnsealer"/> sealed class.
        /// </summary>
        /// <param name="privateKey"></param>
        public CryptoUnsealer(RSA privateKey)
        {
            _privateKey = privateKey;
        }

        /// <summary>
        /// Decrypts the passed package into the passed output folder.
        /// </summary>
        /// <param name="package">The package to decrypt.</param>
        /// <param name="outputFolder">The output folder to decrypt to</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the async operation.</param>
        /// <returns>The decryption operation as a <see cref="Task"/>.</returns>
        [RequiresUnreferencedCode($"Requires reference to {nameof(PackageContainer)}")]
#if NET8_0_OR_GREATER
        [RequiresDynamicCode("Serializes to stream")]
#endif
        public Task Decrypt(Stream package, string outputFolder, CancellationToken cancellationToken = default)
        {
            return Decrypt(
                package,
                key => (
                    true,
                    File.Create(Path.Combine(outputFolder, Path.GetFileNameWithoutExtension(key)), 4096,
                        FileOptions.Asynchronous)), cancellationToken);
        }

        [RequiresUnreferencedCode($"Requires reference to {nameof(PackageContainer)}")]
#if NET8_0_OR_GREATER
        [RequiresDynamicCode("Serializes to stream")]
#endif
        public async Task Decrypt(
            Stream package,
            Func<string, (bool dispose, Stream content)> outputStreamFinder,
            CancellationToken cancellationToken = default)
        {
            var archive = ZipArchive.Open(package);
            var metadataEntry = archive.Entries.First(x => x.Key == "metadata.json");
            var metadataStream = metadataEntry.OpenEntryStream();
            await using var _ = metadataStream.ConfigureAwait(false);
            var metadata = await JsonSerializer.DeserializeAsync<PackageContainer>(
                metadataStream,
                CryptoSettings.SerializerSettings, cancellationToken).ConfigureAwait(false);
            if (metadata == null)
            {
                throw new InvalidDataException("Could not read metadata");
            }

            foreach (var bundle in metadata.Bundles)
            {
                var cryptography = bundle.Cryptography;
                var cryptoProvider = CreateCryptoProvider(cryptography);

                var entry = archive.Entries.First(x => x.Key == bundle.ContentLink);

                var hmac = new HMACSHA256
                {
                    Key = DecryptBytesWithPrivateKey(Convert.FromBase64String(cryptography.AuthKey))
                };
                var hashStream = entry.OpenEntryStream();
                await using var __ = hashStream.ConfigureAwait(false);

                var hashBytes = await hmac.ComputeHashAsync(hashStream, cancellationToken).ConfigureAwait(false);
                var hash = Convert.ToBase64String(hashBytes);

                if (!string.Equals(hash, cryptography.AuthCode))
                {
                    throw new InvalidDataException("Invalid file hash");
                }

                using var decryptor = cryptoProvider.CreateDecryptor();
                var (dispose, outputStream) = outputStreamFinder(entry.Key);
                var contentStream = entry.OpenEntryStream();
                await using var ___ = contentStream.ConfigureAwait(false);
                var cryptoStream = new CryptoStream(contentStream, decryptor, CryptoStreamMode.Read);
                await using var ____ = cryptoStream.ConfigureAwait(false);
                await cryptoStream.CopyToAsync(outputStream, cancellationToken).ConfigureAwait(false);

                if (dispose)
                {
                    outputStream.Close();
                    await outputStream.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        private SymmetricAlgorithm CreateCryptoProvider(Cryptography cryptography)
        {
            SymmetricAlgorithm algo = cryptography.Algorithm switch
            {
                "aes" => Aes.Create(),
                "des" => DES.Create(),
                "tripledes" => TripleDES.Create(),
                "rc2" => RC2.Create(),
                _ => throw new ArgumentException("Unknown or unsupported algorithm", cryptography.Algorithm)
            };

            algo.BlockSize = cryptography.BlockSize;
            algo.KeySize = cryptography.KeySize;
            algo.Mode = cryptography.CipherMode;
            algo.Padding = cryptography.Padding;
            algo.Key = DecryptBytesWithPrivateKey(Convert.FromBase64String(cryptography.EncryptionKey));
            algo.IV = Convert.FromBase64String(cryptography.InitVector);

            return algo;
        }

        private byte[] DecryptBytesWithPrivateKey(byte[] data, RSAEncryptionPadding? padding = null)
        {
            var result = _privateKey.Decrypt(data, padding ?? RSAEncryptionPadding.Pkcs1);
            return result;
        }

        ///<inheritdoc />
        public void Dispose()
        {
            _privateKey.Dispose();
        }
    }
}
