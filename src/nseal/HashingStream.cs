using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace NSeal;

internal sealed class HashingStream : Stream
{
    private readonly Stream _innerStream;
    private readonly byte[]? _key;
    private readonly List<byte> _buffer = [];

    public HashingStream(Stream innerStream, byte[]? key = null)
    {
        _innerStream = innerStream;
        _key = key;
    }

    public override void Flush()
    {
        _innerStream.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var read = _innerStream.Read(buffer, offset, count);
        _buffer.AddRange(buffer.AsSpan(offset, read));
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return _innerStream.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        _innerStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _buffer.AddRange(buffer.AsSpan(offset, count));
        _innerStream.Write(buffer, offset, count);
    }

    public (byte[], byte[]) GetHash()
    {
        using var hmac = _key == null ? new HMACSHA256() : new HMACSHA256(_key);
        return (hmac.Key, hmac.ComputeHash(_buffer.ToArray()));
    }

    public override bool CanRead
    {
        get { return _innerStream.CanRead; }
    }

    public override bool CanSeek
    {
        get { return _innerStream.CanSeek; }
    }

    public override bool CanWrite
    {
        get { return _innerStream.CanWrite; }
    }

    public override long Length
    {
        get { return _innerStream.Length; }
    }

    public override long Position
    {
        get { return _innerStream.Position; }
        set { _innerStream.Position = value; }
    }
}
