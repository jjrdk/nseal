# NSeal

The library focuses on the problem of storing content in insecure storage locations, or transporting content across insecure transport.

## Storage Encryption

Storing content in insecure locations makes it vulnerable to abuse from malicious actors.Nseal provides the ```KeyEnvelope``` to generate a master data encryption key (DEK) and generate a key encryption key (KEK) to encrypt the DEK. The KEK is derived from the user's password and a salt, so is not accessible to an attacker.

This is intended for systems protecting user data with their own keys. It is not a solution for end to end encryption. Never provide private data or password information to a system you do not trust.

The following example shows how to create a key envelope and get the DEK to perform symmetric key encryption:

```csharp
var envelope = await KeyEnvelope.Create("your password");
var dek = await envelope.GetDek("your password");
// perform your own encryption operations
```

The following example shows how to create a key envelope and use it to create encrypted streams to write private data to:

```csharp
var envelope = await KeyEnvelope.Create("your password");
await using var contentStream = new MemoryStream();
var encryption = await envelope.CreateEncryptionStream("your password", contentStream);
await encryption.WriteAsync(content);
await encryption.FlushAsync();
```

The provided stream will flush the final block when the stream is closed or disposed.

## Transport Encryption

Transporting content over insecure transports exposes the content to eavesdropping or manipulation. To prevent this, the data should at least be encrypted (content security), but should also signed to show it has not been altered (integrity check).

Nseal provides the ```CryptoSealer``` class to generate a zip file for encrypted content. When building the encrypted content, the ```CryptoSealer``` uses the public key of the intended recipient to generate (DEK) and protect (KEK) symmetric keys used for content encryption. There is a corresponding ```CryptoUnsealer``` for performing the unpacking of the encrypted content. To decrypt the content, the recipient's private key is required.

The ```CryptoSealer``` and ```CryptoUnsealer``` use asymmetric keys to protect the generated encryption keys to make it easier to perform key exchanges across systems.

The following example shows how to create an encrypted package:

```csharp
var sealer = new CryptoSealer([Recipient RSA]);
await using (var output = File.Create("output.zip"))
{
    var content = new EncryptionContent(
        "item.txt",
        new MemoryStream(Encoding.UTF8.GetBytes("Hello, World")));
    await sealer.Encrypt(new[] { content }, output);
}

// File is now ready for reading or transport.
var readableStream = File.OpenRead("output.zip");
```

See tests for further running examples.

## Reporting Issues and Bugs

When reporting issues and bugs, please provide a clear set of steps to reproduce the issue. The best way is to provide a failing test case as a pull request.

If that is not possible, please provide a set of steps which allow the bug to be reliably reproduced. These steps must also reproduce the issue on a computer that is not your own.

## Contributions

All contributions are appreciated. Please provide them as an issue with an accompanying pull request.

This is an open source project. Work has gone into making it available. Please respect the license terms and the fact that issues and contributions may not be handled as fast as you may wish. The best way to get your contribution adopted is to make it easy to pull into the code base.
