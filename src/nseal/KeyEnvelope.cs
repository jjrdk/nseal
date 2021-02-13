namespace NSeal
{
    using System.IO;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

    /// <summary>
    /// Defines the key envelope class.
    /// </summary>
    public class KeyEnvelope
    {
        private byte[] _salt;
        private const int KeyLength = 32;
        private const int SaltLength = 16;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyEnvelope"/> class.
        /// </summary>
        /// <param name="encryptedDek">The encrypted data encryption key bytes.</param>
        /// <param name="initializationVector">The initialization vector.</param>
        /// <param name="salt">The encryption salt.</param>
        public KeyEnvelope(byte[] encryptedDek, byte[] initializationVector, byte[] salt)
        {
            _salt = salt;
            EncryptedDek = encryptedDek;
            InitializationVector = initializationVector;
        }

        /// <summary>
        /// Creates a new <see cref="KeyEnvelope"/> from the given password.
        /// </summary>
        /// <param name="password">The password to encrypt the key with.</param>
        /// <param name="salt">The password salt</param>
        /// <returns>An instance of a <see cref="KeyEnvelope"/>.</returns>
        public static async Task<KeyEnvelope> Create(string password, byte[]? salt = null)
        {
            using var rng = new RNGCryptoServiceProvider();
            if (salt == null)
            {
                salt = new byte[SaltLength];
                rng.GetBytes(salt);
            }

            var dek = new byte[KeyLength];
            rng.GetBytes(dek);
            using var derivedBytes = new Rfc2898DeriveBytes(password, salt);
            // Encrypt the data.
            using Aes encAlg = Aes.Create();
            encAlg.GenerateIV();
            encAlg.Key = derivedBytes.GetBytes(KeyLength);

            await using MemoryStream encryptionStream = new();
            await using CryptoStream encrypt = new(encryptionStream, encAlg.CreateEncryptor(), CryptoStreamMode.Write);

            await encrypt.WriteAsync(dek, 0, dek.Length).ConfigureAwait(false);
            encrypt.FlushFinalBlock();
            encrypt.Close();
            await encryptionStream.FlushAsync().ConfigureAwait(false);

            var envelope = new KeyEnvelope(encryptionStream.ToArray(), encAlg.IV, salt);
            return envelope;
        }

        /// <summary>
        /// Changes the encryption password for the data encryption key.
        /// </summary>
        /// <param name="oldPassword">The old password</param>
        /// <param name="newPassword">The new password</param>
        /// <returns>A <see cref="Task"/> for the async operation.</returns>
        public async Task ChangePassword(string oldPassword, string newPassword, byte[]? newSalt = null)
        {
            var key = await GetDek(oldPassword).ConfigureAwait(false);
            using var rng = new RNGCryptoServiceProvider();
            newSalt ??= _salt;
            rng.GetBytes(newSalt);
            _salt = newSalt;
            using var derivedBytes = new Rfc2898DeriveBytes(newPassword, _salt);
            using var algo = Aes.Create();
            algo.Key = derivedBytes.GetBytes(KeyLength);
            algo.GenerateIV();
            InitializationVector = algo.IV;

            await using MemoryStream encryptionStream = new();
            await using CryptoStream encrypt = new(encryptionStream, algo.CreateEncryptor(), CryptoStreamMode.Write);

            await encrypt.WriteAsync(key, 0, key.Length).ConfigureAwait(false);
            encrypt.FlushFinalBlock();
            encrypt.Close();
            await encryptionStream.FlushAsync().ConfigureAwait(false);
            EncryptedDek = encryptionStream.ToArray();
        }

        /// <summary>
        /// Gets the data encryption key.
        /// </summary>
        /// <param name="password">The password to decrypt the data encryption key.</param>
        /// <returns>The data encryption key as a <see cref="Task{T}"/></returns>
        public async Task<byte[]> GetDek(string password)
        {
            using var deriveBytes = new Rfc2898DeriveBytes(password, _salt);

            using Aes decAlg = Aes.Create();
            decAlg.Key = deriveBytes.GetBytes(KeyLength);
            decAlg.IV = InitializationVector;

            var key = new byte[KeyLength];
            // Try to decrypt, thus showing it can be round-tripped.
            await using MemoryStream decryptionStreamBacking = new(EncryptedDek);
            await using CryptoStream decrypt = new(
                decryptionStreamBacking,
                decAlg.CreateDecryptor(),
                CryptoStreamMode.Read);
            await decrypt.ReadAsync(key, 0, key.Length).ConfigureAwait(false);
            await decrypt.FlushAsync().ConfigureAwait(false);
            decrypt.Close();
            decryptionStreamBacking.Close();
            return key;
        }

        public async Task<Stream> CreateEncryptionStream(string password, Stream outputStream)
        {
            var key = await GetDek(password).ConfigureAwait(false);
            return new PasswordEncryptionStream(key, outputStream);
        }

        public async Task<Stream> CreateDecryptionStream(string password, Stream inputStream)
        {
            var key = await GetDek(password).ConfigureAwait(false);
            return new PasswordDecryptionStream(key, inputStream);
        }

        /// <summary>
        /// Gets the encrypted data encrypted key.
        /// </summary>
        public byte[] EncryptedDek { get; private set; }

        /// <summary>
        /// Gets the encryption initialization vector.
        /// </summary>
        public byte[] InitializationVector { get; private set; }
    }
}