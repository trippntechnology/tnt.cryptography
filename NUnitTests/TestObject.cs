using System.Diagnostics.CodeAnalysis;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
internal class TestObject
{
  public Guid ApplicationID { get; set; }
  public Guid LicenseID { get; set; }
  public string Secret { get; set; } = string.Empty;
  public string ServiceEndpoint { get; set; } = string.Empty;
}
