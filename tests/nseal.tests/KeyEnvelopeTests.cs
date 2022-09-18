namespace NSeal.Tests
{
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using Xunit;

    public sealed class KeyEnvelopeTests
    {
        private const string OldPassword = "old password";
        private const string Password = "password";

        [Fact]
        public async Task WhenCreatingKeyEnvelopeThenCanGetDekWithPassword()
        {
            var envelope = await KeyEnvelope.Create(Password).ConfigureAwait(false);
            var dek = await envelope.GetDek(Password).ConfigureAwait(false);

            Assert.NotEmpty(dek);
        }

        [Fact]
        public async Task WhenCreatingKeyEnvelopeThenCannotGetDekWithWrongPassword()
        {
            var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            var envelope = await KeyEnvelope.Create(Password).ConfigureAwait(false);
            var dek = await envelope.GetDek(Password).ConfigureAwait(false);
            var algo = Aes.Create();
            algo.Key = dek;
            algo.GenerateIV();
            await using var output = new MemoryStream();
            await using var encrypt = new CryptoStream(output, algo.CreateEncryptor(), CryptoStreamMode.Write);
            await encrypt.WriteAsync(data).ConfigureAwait(false);
            await encrypt.FlushFinalBlockAsync().ConfigureAwait(false);

            algo.Key = await envelope.GetDek("blah").ConfigureAwait(false);
            output.Position = 0;
            await using var decrypt = new CryptoStream(output, algo.CreateDecryptor(), CryptoStreamMode.Read);
            var buffer = new byte[9];

            await Assert.ThrowsAsync<CryptographicException>(() => decrypt.ReadAsync(buffer).AsTask()).ConfigureAwait(false);
        }

        [Fact]
        public async Task WhenChangingPasswordThenCannotGetDekWithOldPassword()
        {
            var envelope = await KeyEnvelope.Create(OldPassword).ConfigureAwait(false);
            var dek = await envelope.GetDek(OldPassword).ConfigureAwait(false);

            await envelope.ChangePassword(OldPassword, "new password").ConfigureAwait(false);

            var newDek = await envelope.GetDek(OldPassword).ConfigureAwait(false);

            Assert.NotEqual(dek, newDek);
        }

        [Fact]
        public async Task CanRecreateEnvelopFromJson()
        {
            var salt = Enumerable.Range(0, 16).Select(x => (byte)x).ToArray();
            var converter = new KeyEnvelopeConverter(salt);

            var envelope = await KeyEnvelope.Create(Password, salt).ConfigureAwait(false);
            var json = JsonConvert.SerializeObject(envelope, converter);

            var recreated = JsonConvert.DeserializeObject<KeyEnvelope>(json, converter);

            Assert.Equal(envelope.EncryptedDek, recreated!.EncryptedDek);
            Assert.Equal(envelope.InitializationVector, recreated.InitializationVector);
        }

        [Fact]
        public async Task CanRoundtripEncryption()
        {
            var envelope = await KeyEnvelope.Create(Password).ConfigureAwait(false);
            const string helloWorld = "Hello, World";
            var content = Encoding.UTF8.GetBytes(helloWorld);
            await using var contentStream = new MemoryStream();
            await using (var encryption =
                     await envelope.CreateEncryptionStream(Password, contentStream).ConfigureAwait(false))
            {
                await encryption.WriteAsync(content).ConfigureAwait(false);
                await encryption.FlushAsync().ConfigureAwait(false);
            }
            
            contentStream.Position = 0;

            var decryption = await envelope.CreateDecryptionStream(Password, contentStream).ConfigureAwait(false);
            var buffer = new byte[100];
            var read = await decryption.ReadAsync(buffer).ConfigureAwait(false);

            Assert.Equal(helloWorld, Encoding.UTF8.GetString(buffer, 0, read));
        }
    }
}