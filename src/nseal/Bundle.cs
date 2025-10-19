namespace NSeal;

using System;

internal sealed class Bundle
{
    public DateTimeOffset AssemblyTime { get; init; } = DateTimeOffset.UtcNow;

    public string ContentLink { get; init; } = string.Empty;

    public Cryptography Cryptography { get; init; } = new();
}
