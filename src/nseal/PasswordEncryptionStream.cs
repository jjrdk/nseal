namespace NSeal
{
    using System.IO;
    using System.Security.Cryptography;

    internal sealed class PasswordEncryptionStream : Stream
    {
        private readonly CryptoStream _cryptoStream;

        internal PasswordEncryptionStream(byte[] dataEncryptionKey, Stream outputStream)
        {
            var algo = Aes.Create();
            algo.GenerateIV();
            algo.Key = dataEncryptionKey;

            outputStream.Write(algo.IV);
            _cryptoStream = new CryptoStream(outputStream, algo.CreateEncryptor(), CryptoStreamMode.Write);
        }

        /// <inheritdoc />
        public override void Flush() => _cryptoStream.Flush();

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count) => _cryptoStream.Read(buffer, offset, count);

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin) => _cryptoStream.Seek(offset, origin);

        /// <inheritdoc />
        public override void SetLength(long value) => _cryptoStream.SetLength(value);

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            _cryptoStream.Write(buffer, offset, count);
        }

        /// <inheritdoc />
        public override bool CanRead => _cryptoStream.CanRead;

        /// <inheritdoc />
        public override bool CanSeek => _cryptoStream.CanSeek;

        /// <inheritdoc />
        public override bool CanWrite => _cryptoStream.CanWrite;

        /// <inheritdoc />
        public override long Length => _cryptoStream.Length;

        /// <inheritdoc />
        public override long Position
        {
            get => _cryptoStream.Position;
            set => _cryptoStream.Position = value;
        }

        /// <inheritdoc />
        public override void Close()
        {
            _cryptoStream.FlushFinalBlock();
            base.Close();
        }
    }

    internal sealed class PasswordDecryptionStream : Stream
    {
        private readonly CryptoStream _cryptoStream;

        internal PasswordDecryptionStream(byte[] dataEncryptionKey, Stream inputStream)
        {
            var iv = new byte[16];
            var read = inputStream.Read(iv, 0, 16);
            if (read != iv.Length)
            {
                throw new EndOfStreamException();
            }
            var algo = Aes.Create();
            algo.IV = iv;
            algo.Key = dataEncryptionKey;

            _cryptoStream = new CryptoStream(inputStream, algo.CreateDecryptor(), CryptoStreamMode.Read);
        }

        /// <inheritdoc />
        public override void Flush() => _cryptoStream.Flush();

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count) => _cryptoStream.Read(buffer, offset, count);

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin) => _cryptoStream.Seek(offset, origin);

        /// <inheritdoc />
        public override void SetLength(long value) => _cryptoStream.SetLength(value);

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            _cryptoStream.Write(buffer, offset, count);
        }

        /// <inheritdoc />
        public override bool CanRead => _cryptoStream.CanRead;

        /// <inheritdoc />
        public override bool CanSeek => _cryptoStream.CanSeek;

        /// <inheritdoc />
        public override bool CanWrite => _cryptoStream.CanWrite;

        /// <inheritdoc />
        public override long Length => _cryptoStream.Length;

        /// <inheritdoc />
        public override long Position
        {
            get => _cryptoStream.Position;
            set => _cryptoStream.Position = value;
        }
    }
}