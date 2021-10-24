namespace NSeal.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using PemUtils;
    using Xunit;

    public class AlgorithmTests
    {
        private const string HelloWorld = "Hello, World";

        [Theory]
        [MemberData(nameof(GetAlgoParams))]
        public async Task CanEncryptWithDifferentAlgorithmsConfigurations(SymmetricAlgorithm algorithm, int blockSize, int keySize, CipherMode mode, PaddingMode padding)
        {
            algorithm.BlockSize = blockSize;
            algorithm.KeySize = keySize;
            algorithm.Mode = mode;
            algorithm.Padding = padding;
            algorithm.GenerateKey();
            algorithm.GenerateIV();

            await using var file = File.OpenRead("test.pem");
            using var reader = new PemReader(file);
            using var cryptoStreamer = new CryptoSealer(
                RSA.Create(reader.ReadRsaKey()),
                () => algorithm);

            await using var output = new MemoryStream();
            await using var contentStream = new MemoryStream(Encoding.UTF8.GetBytes(HelloWorld));
            await cryptoStreamer.Encrypt(new[] { new EncryptionContent("item.txt", contentStream) }, output).ConfigureAwait(false);
            output.Position = 0;

            var pemReader = new PemReader(File.OpenRead("test.ppk"), true);
            var parameters = pemReader.ReadRsaKey();
            var rsa = RSA.Create(parameters);
            var decryptStreamer = new CryptoUnsealer(rsa);

            await using var ms = new MemoryStream();
            await decryptStreamer.Decrypt(output, _ => (false, ms)).ConfigureAwait(false);
            ms.Position = 0;

            using var resultReader = new StreamReader(ms);
            var result = await resultReader.ReadToEndAsync().ConfigureAwait(false);

            Assert.Equal(HelloWorld, result.Trim('\0'));
        }

        public static IEnumerable<object[]> GetAlgoParams()
        {
            return from symmetric in new SymmetricAlgorithm[] { Aes.Create(), DES.Create(), TripleDES.Create(), RC2.Create() }
                   from blockSize in symmetric.LegalBlockSizes.SelectMany(GenerateKeySizes)
                   from keySize in symmetric.LegalKeySizes.SelectMany(GenerateKeySizes)
                   from mode in new[] { CipherMode.CBC, CipherMode.ECB }
                   from padding in Enum.GetValues<PaddingMode>().Where(p => p != PaddingMode.None)
                   select new object[] { symmetric, blockSize, keySize, mode, padding };
        }

        private static IEnumerable<int> GenerateKeySizes(KeySizes k)
        {
            var size = k.MinSize;
            while (true)
            {
                yield return size;
                if (size == k.MaxSize)
                {
                    yield break;
                }

                size += k.SkipSize;
            }
        }
    }
}