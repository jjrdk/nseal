using System.Text.Json.Serialization;

namespace NSeal
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.Serialization;

    internal sealed class PackageContainer
    {
        [JsonPropertyName("created")]
        public DateTimeOffset Created { get; set; }

        [JsonPropertyName("bundles")]
        public ICollection<Bundle> Bundles { get; set; } = new List<Bundle>();
    }
}
