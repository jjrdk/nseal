namespace NSeal
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using SharpCompress.Archives.Zip;

    public class CryptoUnsealer : IDisposable
    {
        private readonly RSA _privateKey;
        private readonly JsonSerializer _serializer = JsonSerializer.Create(CryptoSettings.SerializerSettings);

        public CryptoUnsealer(RSA privateKey)
        {
            _privateKey = privateKey;
        }

        public Task Decrypt(Stream package, string outputFolder)
        {
            return Decrypt(
                package,
                key => (true, File.Create(Path.Combine(outputFolder, Path.GetFileNameWithoutExtension(key) ?? key), 4096, FileOptions.Asynchronous)));
        }

        public async Task Decrypt(
            Stream package,
            Func<string, (bool dispose, Stream content)> outputStreamFinder,
            CancellationToken cancellationToken = default)
        {
            var archive = ZipArchive.Open(package);
            var metadataEntry = archive.Entries.First(x => x.Key == "metadata.json");
            await using var metadataStream = metadataEntry.OpenEntryStream();
            using var reader = new StreamReader(metadataStream);
            var jsonReader = new JsonTextReader(reader);
            var metadata = _serializer.Deserialize<PackageContainer>(jsonReader);
            if (metadata == null)
            {
                throw new InvalidDataException("Could not read metadata");
            }

            foreach (var bundle in metadata.Bundles)
            {
                var cryptography = bundle.Cryptography;
                var cryptoProvider = CreateCryptoProvider(cryptography);

                var entry = archive.Entries.First(x => x.Key == bundle.ContentLink);

                var hmac = HMAC.Create("HMACSHA256")!;
                hmac.Key = DecryptBytesWithPrivateKey(Convert.FromBase64String(cryptography.AuthKey));

                await using var hashStream = entry.OpenEntryStream();
                var hashBytes = hmac.ComputeHash(hashStream);
                var hash = Convert.ToBase64String(hashBytes);

                if (!string.Equals(hash, cryptography.AuthCode))
                {
                    throw new InvalidDataException("Invalid file hash");
                }

                using var decryptor = cryptoProvider.CreateDecryptor();
                var (dispose, outputStream) = outputStreamFinder(entry.Key);
                await using var contentStream = entry.OpenEntryStream();
                await using var cryptoStream = new CryptoStream(contentStream, decryptor, CryptoStreamMode.Read);
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
                "aes" => Aes.Create()!,
                "rijndael" => Rijndael.Create()!,
                "des" => DES.Create()!,
                "tripledes" => TripleDES.Create()!,
                "rc2" => RC2.Create()!,
                _ => throw new ArgumentException("Unknown algorithm", cryptography.Algorithm)
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

        public void Dispose()
        {
            _privateKey.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}