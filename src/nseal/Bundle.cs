namespace NSeal
{
    using System;
    using System.Runtime.Serialization;

    [DataContract]
    internal sealed class Bundle
    {
        [DataMember(Name = "assemblyTime")]
        public DateTimeOffset AssemblyTime { get; set; } = DateTimeOffset.Now;

        [DataMember(Name = "contentLink")]
        public string ContentLink { get; set; } = string.Empty;

        [DataMember(Name = "cryptography")]
        public Cryptography Cryptography { get; set; } = new Cryptography();
    }
}