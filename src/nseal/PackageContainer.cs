namespace NSeal
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.Serialization;

    [DataContract]
    internal class PackageContainer
    {
        [DataMember(Name = "created")]
        public DateTimeOffset Created { get; set; }

        [DataMember(Name = "bundle")]
        public ICollection<Bundle> Bundle { get; set; } = new List<Bundle>();
    }
}