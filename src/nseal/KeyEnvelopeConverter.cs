﻿namespace NSeal
{
    using System;
    using Newtonsoft.Json;

    /// <summary>
    /// Defines the <see cref="KeyEnvelope"/> converter.
    /// </summary>
    public class KeyEnvelopeConverter : JsonConverter<KeyEnvelope>
    {
        private readonly byte[] _systemSalt;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyEnvelopeConverter"/> class.
        /// </summary>
        /// <param name="systemSalt"></param>
        public KeyEnvelopeConverter(byte[] systemSalt)
        {
            _systemSalt = systemSalt;
        }

        /// <inheritdoc />
        public override void WriteJson(JsonWriter writer, KeyEnvelope? value, JsonSerializer serializer)
        {
            if(value == null)
            {
                writer.WriteNull();
                return;
            }
            writer.WriteStartObject();
            writer.WritePropertyName("dek");
            serializer.Serialize(writer, value.EncryptedDek);
            writer.WritePropertyName("iv");
            serializer.Serialize(writer, value.InitializationVector);
            writer.WriteEndObject();
        }

        /// <inheritdoc />
        public override KeyEnvelope ReadJson(
            JsonReader reader,
            Type objectType,
            KeyEnvelope? existingValue,
            bool hasExistingValue,
            JsonSerializer serializer)
        {
            byte[]? dek = null;
            byte[]? iv = null;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonToken.PropertyName:
                        switch (reader.Path)
                        {
                            case "dek":
                                dek = reader.ReadAsBytes();
                                break;
                            case "iv":
                                iv = reader.ReadAsBytes();
                                break;
                        }
                        break;
                }
            }

            if (dek == null || iv == null)
            {
                throw new JsonException("Missing values");
            }

            return new KeyEnvelope(dek, iv, _systemSalt);
        }
    }
}