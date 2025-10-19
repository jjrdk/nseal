using System.Text.Json;
using System.Text.Json.Serialization;

namespace NSeal;

using System;

/// <summary>
/// Defines the <see cref="KeyEnvelope"/> converter.
/// </summary>
public sealed class KeyEnvelopeConverter : JsonConverter<KeyEnvelope>
{
    private readonly byte[] _systemSalt;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyEnvelopeConverter"/> sealed class.
    /// </summary>
    /// <param name="systemSalt"></param>
    public KeyEnvelopeConverter(byte[] systemSalt)
    {
        _systemSalt = systemSalt;
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, KeyEnvelope value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteBase64String("dek", value.EncryptedDek);
        writer.WriteBase64String("iv", value.InitializationVector);
        writer.WriteEndObject();
    }

    /// <inheritdoc />
    public override KeyEnvelope Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        byte[]? dek = null;
        byte[]? iv = null;
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.PropertyName:
                    switch (reader.GetString())
                    {
                        case "dek":
                            reader.Read();
                            dek = reader.GetBytesFromBase64();
                            break;
                        case "iv":
                            reader.Read();
                            iv = reader.GetBytesFromBase64();
                            break;
                    }

                    break;
                default:
                    continue;
            }
        }

        if (dek == null || iv == null)
        {
            throw new JsonException("Missing values");
        }

        return new KeyEnvelope(dek, iv, _systemSalt);
    }
}