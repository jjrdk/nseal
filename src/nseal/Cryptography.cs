namespace NSeal
{
    using System.Runtime.Serialization;
    using System.Security.Cryptography;

    [DataContract]
    internal class Cryptography
    {
        [DataMember(Name = "algorithm")]
        public string Algorithm { get; set; }

        [DataMember(Name = "blockSize")]
        public int BlockSize { get; set; }

        [DataMember(Name = "keySize")]
        public int KeySize { get; set; }

        [DataMember(Name = "cipherMode")]
        public CipherMode CipherMode { get; set; }

        [DataMember(Name = "padding")]
        public PaddingMode Padding { get; set; }

        [DataMember(Name = "encryptionKey")]
        public string EncryptionKey { get; set; }

        [DataMember(Name = "initVector")]
        public string InitVector { get; set; }

        [DataMember(Name = "authKey")]
        public string AuthKey { get; set; }

        [DataMember(Name = "authCode")]
        public string AuthCode { get; set; }
    }
}