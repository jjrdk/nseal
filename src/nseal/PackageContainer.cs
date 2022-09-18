namespace NSeal
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.Serialization;

    [DataContract]
    internal sealed class PackageContainer
    {
        [DataMember(Name = "created")]
        public DateTimeOffset Created { get; set; }

        [DataMember(Name = "bundles")]
        public ICollection<Bundle> Bundles { get; set; } = new List<Bundle>();
    }
}