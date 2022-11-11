namespace NSeal.Tests
{
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using PemUtils;
    using SharpCompress.Archives.Zip;
    using Xunit;

    public sealed class PfxEncryptionTests
    {
        private const string HelloWorld = "Hello, World";
        readonly CryptoSealer _cryptoStreamer = null;
        private readonly CryptoUnsealer _cryptoUnsealer = null;

        public PfxEncryptionTests()
        {
            var cert = new X509Certificate2("testcert.pfx", "test", X509KeyStorageFlags.Exportable);
            using var file = File.OpenRead("test.pem");

            using var reader = new PemReader(file);
            _cryptoStreamer = new CryptoSealer(RSA.Create(reader.ReadRsaKey()));
            _cryptoUnsealer = new CryptoUnsealer(cert.GetRSAPrivateKey());
        }

        [Fact]
        public async Task CanDecryptContent()
        {
            var output = await CreatePackage().ConfigureAwait(false);
            await using var _ = output.ConfigureAwait(false);

            await _cryptoUnsealer.Decrypt(output, Path.GetFullPath("./")).ConfigureAwait(false);
            _cryptoUnsealer.Dispose();
            await output.DisposeAsync().ConfigureAwait(false);

            var content = File.OpenRead("item.txt");
            await using var __ = content.ConfigureAwait(false);
            using var reader = new StreamReader(content);
            var text = await reader.ReadToEndAsync().ConfigureAwait(false);

            Assert.Equal(HelloWorld, text);
        }

        [Fact]
        public async Task CanReadBackMetadata()
        {
            var output = await CreatePackage().ConfigureAwait(false);
            await using var _ = output.ConfigureAwait(false);
            var outputArchive = ZipArchive.Open(output);

            var entry = outputArchive.Entries.First(x => x.Key == "metadata.json");
            var entryStream = entry.OpenEntryStream();
            await using var __ = entryStream.ConfigureAwait(false);
            using var streamReader = new StreamReader(entryStream);
            var json = await streamReader.ReadToEndAsync().ConfigureAwait(false);

            var metadata = JsonConvert.DeserializeObject<PackageContainer>(json);
            Assert.Single(metadata.Bundles);
        }

        private async Task<Stream> CreatePackage()
        {
            var output = File.Create("output.zip");
            await using (output.ConfigureAwait(false))
            {
                var content = new EncryptionContent(
                    "item.txt",
                    new MemoryStream(Encoding.UTF8.GetBytes(HelloWorld)));
                await _cryptoStreamer.Encrypt(new[] { content }, output).ConfigureAwait(false);
            }

            return File.OpenRead("output.zip");
        }
    }
}
