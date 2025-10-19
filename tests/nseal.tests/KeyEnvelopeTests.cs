namespace NSeal.Tests;

using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

public sealed class KeyEnvelopeTests
{
    private const string OldPassword = "old password";
    private const string Password = "password";

    [Fact]
    public async Task WhenCreatingKeyEnvelopeThenCanGetDekWithPassword()
    {
        var envelope = await KeyEnvelope.Create(Password);
        var dek = await envelope.GetDek(Password);

        Assert.NotEmpty(dek);
    }

    [Fact]
    public async Task WhenCreatingKeyEnvelopeThenCannotGetDekWithWrongPassword()
    {
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        var envelope = await KeyEnvelope.Create(Password);
        var dek = await envelope.GetDek(Password);
        var algo = Aes.Create();
        algo.Key = dek;
        algo.GenerateIV();
        var output = new MemoryStream();
        await using var _ = output.ConfigureAwait(false);
        var encrypt = new CryptoStream(output, algo.CreateEncryptor(), CryptoStreamMode.Write);
        await using var __ = encrypt.ConfigureAwait(false);
        await encrypt.WriteAsync(data);
        await encrypt.FlushFinalBlockAsync();

        algo.Key = await envelope.GetDek("blah");
        output.Position = 0;
        var decrypt = new CryptoStream(output, algo.CreateDecryptor(), CryptoStreamMode.Read);
        await using var ___ = decrypt.ConfigureAwait(false);
        var buffer = new byte[9];

        await Assert.ThrowsAsync<CryptographicException>(() => decrypt.ReadAsync(buffer).AsTask());
    }

    [Fact]
    public async Task WhenChangingPasswordThenCannotGetDekWithOldPassword()
    {
        var envelope = await KeyEnvelope.Create(OldPassword);
        var dek = await envelope.GetDek(OldPassword);

        await envelope.ChangePassword(OldPassword, "new password");

        var newDek = await envelope.GetDek(OldPassword);

        Assert.NotEqual(dek, newDek);
    }

    [Fact]
    public async Task CanRecreateEnvelopFromJson()
    {
        var salt = Enumerable.Range(0, 16).Select(x => (byte)x).ToArray();
        //var converter = new KeyEnvelopeConverter(salt);

        var serializerOptions = CryptoSettings.Create(Encoding.UTF8.GetBytes(Password));
        var envelope = await KeyEnvelope.Create(Password, salt);
        var json = System.Text.Json.JsonSerializer.Serialize(envelope, serializerOptions);

        var recreated = System.Text.Json.JsonSerializer.Deserialize<KeyEnvelope>(json, serializerOptions);

        Assert.Equal(envelope.EncryptedDek, recreated!.EncryptedDek);
        Assert.Equal(envelope.InitializationVector, recreated.InitializationVector);
    }

    [Fact]
    public async Task CanRoundtripEncryption()
    {
        var envelope = await KeyEnvelope.Create(Password);
        const string helloWorld = "Hello, World";
        var content = Encoding.UTF8.GetBytes(helloWorld);
        var contentStream = new MemoryStream();
        await using var _ = contentStream.ConfigureAwait(false);
        var encryption =
            await envelope.CreateEncryptionStream(Password, contentStream);
        await using (encryption.ConfigureAwait(false))
        {
            await encryption.WriteAsync(content);
            await encryption.FlushAsync();
        }

        contentStream.Position = 0;

        var decryption = await envelope.CreateDecryptionStream(Password, contentStream);
        var buffer = new byte[100];
        var read = await decryption.ReadAsync(buffer);

        Assert.Equal(helloWorld, Encoding.UTF8.GetString(buffer, 0, read));
    }
}