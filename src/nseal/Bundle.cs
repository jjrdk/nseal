namespace NSeal
{
    using System;

    internal sealed class Bundle
    {
        public DateTimeOffset AssemblyTime { get; set; } = DateTimeOffset.UtcNow;

        public string ContentLink { get; set; } = string.Empty;

        public Cryptography Cryptography { get; set; } = new();
    }
}
