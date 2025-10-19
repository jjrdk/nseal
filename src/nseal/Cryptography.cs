namespace NSeal
{
    using System.Security.Cryptography;

    internal sealed class Cryptography
    {
        public string Algorithm { get; init; } = string.Empty;

        public int BlockSize { get; init; }

        public int KeySize { get; init; }

        public CipherMode CipherMode { get; init; }

        public PaddingMode Padding { get; init; }

        public string EncryptionKey { get; init; } = string.Empty;

        public string InitVector { get; init; } = string.Empty;

        public string AuthKey { get; init; } = string.Empty;
        public string AuthCode { get; init; } = string.Empty;
    }
}
