namespace NSeal
{
    using System.Security.Cryptography;

    internal sealed class Cryptography
    {
        public string Algorithm { get; set; } = string.Empty;

        public int BlockSize { get; set; }

        public int KeySize { get; set; }

        public CipherMode CipherMode { get; set; }

        public PaddingMode Padding { get; set; }

        public string EncryptionKey { get; set; } = string.Empty;

        public string InitVector { get; set; } = string.Empty;

        public string AuthKey { get; set; } = string.Empty;

        public string AuthCode { get; set; } = string.Empty;
    }
}
