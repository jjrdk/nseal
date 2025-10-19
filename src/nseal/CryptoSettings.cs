using System.Text.Json;
using System.Text.Json.Serialization;

namespace NSeal;

internal static class CryptoSettings
{
    static CryptoSettings()
    {
        SerializerSettings = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true, NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
            IgnoreReadOnlyFields = true, WriteIndented = false,
//                DateFormatHandling = DateFormatHandling.IsoDateFormat,
//                DateParseHandling = DateParseHandling.DateTimeOffset,
//                DateTimeZoneHandling = DateTimeZoneHandling.RoundtripKind,
//                DefaultValueHandling = DefaultValueHandling.Ignore,
//                FloatFormatHandling = FloatFormatHandling.DefaultValue,
//                FloatParseHandling = FloatParseHandling.Double,
//                Formatting = Formatting.None,
//                MetadataPropertyHandling = MetadataPropertyHandling.Default,
//                TypeNameHandling = TypeNameHandling.Auto,
//                MissingMemberHandling = MissingMemberHandling.Ignore,
//                NullValueHandling = NullValueHandling.Ignore
        };
        //SerializerSettings.Converters.Add(new KeyEnvelopeConverter());
//            SerializerSettings.Converters.Add(new StringEnumConverter(new CamelCaseNamingStrategy()));
    }

    public static JsonSerializerOptions Create(byte[] salt)
    {
        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true, NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
            IgnoreReadOnlyFields = true, WriteIndented = false,
        };

        options.Converters.Add(new KeyEnvelopeConverter(salt));
        return options;
    }

    public static JsonSerializerOptions SerializerSettings { get; }
}