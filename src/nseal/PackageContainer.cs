namespace NSeal;

using System;
using System.Collections.Generic;

internal sealed class PackageContainer
{
    public DateTimeOffset Created { get; set; }

    public ICollection<Bundle> Bundles { get; set; } = new List<Bundle>();
}