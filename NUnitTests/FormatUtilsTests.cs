using System.Diagnostics.CodeAnalysis;
using System.Text;
using TNT.Cryptography;

namespace NUnitTests;

[ExcludeFromCodeCoverage]
public class FormatUtilsTests
{
  private const string testString = @"Duis vel nibh at velit scelerisque suscipit. Vivamus elementum semper nisi. Suspendisse pulvinar, augue ac venenatis condimentum, sem libero volutpat nibh, nec pellentesque velit pede quis nunc. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Vivamus aliquet elit ac nisl.

Pellentesque libero tortor, tincidunt et, tincidunt eget, semper nec, quam. Morbi mattis ullamcorper velit. Fusce commodo aliquam arcu. Curabitur suscipit suscipit tellus. Quisque malesuada placerat nisl.

Nullam vel sem. Etiam sit amet orci eget eros faucibus tincidunt. Praesent ac sem eget est egestas volutpat. Vivamus laoreet. Morbi mattis ullamcorper velit.

Fusce fermentum. Phasellus tempus. Fusce vulputate eleifend sapien. Phasellus viverra nulla ut metus varius laoreet. Vestibulum turpis sem, aliquet eget, lobortis pellentesque, rutrum eu, nisl.

Duis lobortis massa imperdiet quam. Phasellus gravida semper nisi. Pellentesque commodo eros a enim. Suspendisse faucibus, nunc et pellentesque egestas, lacus ante convallis tellus, vitae iaculis lacus elit id tortor. Fusce vel dui.";

  private const string expected80 = @"--- BEGIN ---
RHVpcyB2ZWwgbmliaCBhdCB2ZWxpdCBzY2VsZXJpc3F1ZSBzdXNjaXBpdC4gVml2YW11cyBlbGVtZW50
dW0gc2VtcGVyIG5pc2kuIFN1c3BlbmRpc3NlIHB1bHZpbmFyLCBhdWd1ZSBhYyB2ZW5lbmF0aXMgY29u
ZGltZW50dW0sIHNlbSBsaWJlcm8gdm9sdXRwYXQgbmliaCwgbmVjIHBlbGxlbnRlc3F1ZSB2ZWxpdCBw
ZWRlIHF1aXMgbnVuYy4gQWVuZWFuIGxlbyBsaWd1bGEsIHBvcnR0aXRvciBldSwgY29uc2VxdWF0IHZp
dGFlLCBlbGVpZmVuZCBhYywgZW5pbS4gVml2YW11cyBhbGlxdWV0IGVsaXQgYWMgbmlzbC4NCg0KUGVs
bGVudGVzcXVlIGxpYmVybyB0b3J0b3IsIHRpbmNpZHVudCBldCwgdGluY2lkdW50IGVnZXQsIHNlbXBl
ciBuZWMsIHF1YW0uIE1vcmJpIG1hdHRpcyB1bGxhbWNvcnBlciB2ZWxpdC4gRnVzY2UgY29tbW9kbyBh
bGlxdWFtIGFyY3UuIEN1cmFiaXR1ciBzdXNjaXBpdCBzdXNjaXBpdCB0ZWxsdXMuIFF1aXNxdWUgbWFs
ZXN1YWRhIHBsYWNlcmF0IG5pc2wuDQoNCk51bGxhbSB2ZWwgc2VtLiBFdGlhbSBzaXQgYW1ldCBvcmNp
IGVnZXQgZXJvcyBmYXVjaWJ1cyB0aW5jaWR1bnQuIFByYWVzZW50IGFjIHNlbSBlZ2V0IGVzdCBlZ2Vz
dGFzIHZvbHV0cGF0LiBWaXZhbXVzIGxhb3JlZXQuIE1vcmJpIG1hdHRpcyB1bGxhbWNvcnBlciB2ZWxp
dC4NCg0KRnVzY2UgZmVybWVudHVtLiBQaGFzZWxsdXMgdGVtcHVzLiBGdXNjZSB2dWxwdXRhdGUgZWxl
aWZlbmQgc2FwaWVuLiBQaGFzZWxsdXMgdml2ZXJyYSBudWxsYSB1dCBtZXR1cyB2YXJpdXMgbGFvcmVl
dC4gVmVzdGlidWx1bSB0dXJwaXMgc2VtLCBhbGlxdWV0IGVnZXQsIGxvYm9ydGlzIHBlbGxlbnRlc3F1
ZSwgcnV0cnVtIGV1LCBuaXNsLg0KDQpEdWlzIGxvYm9ydGlzIG1hc3NhIGltcGVyZGlldCBxdWFtLiBQ
aGFzZWxsdXMgZ3JhdmlkYSBzZW1wZXIgbmlzaS4gUGVsbGVudGVzcXVlIGNvbW1vZG8gZXJvcyBhIGVu
aW0uIFN1c3BlbmRpc3NlIGZhdWNpYnVzLCBudW5jIGV0IHBlbGxlbnRlc3F1ZSBlZ2VzdGFzLCBsYWN1
cyBhbnRlIGNvbnZhbGxpcyB0ZWxsdXMsIHZpdGFlIGlhY3VsaXMgbGFjdXMgZWxpdCBpZCB0b3J0b3Iu
IEZ1c2NlIHZlbCBkdWku
--- END ---";

  private const string expected50 = @"--- BEGIN ---
RHVpcyB2ZWwgbmliaCBhdCB2ZWxpdCBzY2VsZXJpc3F1ZSBzdX
NjaXBpdC4gVml2YW11cyBlbGVtZW50dW0gc2VtcGVyIG5pc2ku
IFN1c3BlbmRpc3NlIHB1bHZpbmFyLCBhdWd1ZSBhYyB2ZW5lbm
F0aXMgY29uZGltZW50dW0sIHNlbSBsaWJlcm8gdm9sdXRwYXQg
bmliaCwgbmVjIHBlbGxlbnRlc3F1ZSB2ZWxpdCBwZWRlIHF1aX
MgbnVuYy4gQWVuZWFuIGxlbyBsaWd1bGEsIHBvcnR0aXRvciBl
dSwgY29uc2VxdWF0IHZpdGFlLCBlbGVpZmVuZCBhYywgZW5pbS
4gVml2YW11cyBhbGlxdWV0IGVsaXQgYWMgbmlzbC4NCg0KUGVs
bGVudGVzcXVlIGxpYmVybyB0b3J0b3IsIHRpbmNpZHVudCBldC
wgdGluY2lkdW50IGVnZXQsIHNlbXBlciBuZWMsIHF1YW0uIE1v
cmJpIG1hdHRpcyB1bGxhbWNvcnBlciB2ZWxpdC4gRnVzY2UgY2
9tbW9kbyBhbGlxdWFtIGFyY3UuIEN1cmFiaXR1ciBzdXNjaXBp
dCBzdXNjaXBpdCB0ZWxsdXMuIFF1aXNxdWUgbWFsZXN1YWRhIH
BsYWNlcmF0IG5pc2wuDQoNCk51bGxhbSB2ZWwgc2VtLiBFdGlh
bSBzaXQgYW1ldCBvcmNpIGVnZXQgZXJvcyBmYXVjaWJ1cyB0aW
5jaWR1bnQuIFByYWVzZW50IGFjIHNlbSBlZ2V0IGVzdCBlZ2Vz
dGFzIHZvbHV0cGF0LiBWaXZhbXVzIGxhb3JlZXQuIE1vcmJpIG
1hdHRpcyB1bGxhbWNvcnBlciB2ZWxpdC4NCg0KRnVzY2UgZmVy
bWVudHVtLiBQaGFzZWxsdXMgdGVtcHVzLiBGdXNjZSB2dWxwdX
RhdGUgZWxlaWZlbmQgc2FwaWVuLiBQaGFzZWxsdXMgdml2ZXJy
YSBudWxsYSB1dCBtZXR1cyB2YXJpdXMgbGFvcmVldC4gVmVzdG
lidWx1bSB0dXJwaXMgc2VtLCBhbGlxdWV0IGVnZXQsIGxvYm9y
dGlzIHBlbGxlbnRlc3F1ZSwgcnV0cnVtIGV1LCBuaXNsLg0KDQ
pEdWlzIGxvYm9ydGlzIG1hc3NhIGltcGVyZGlldCBxdWFtLiBQ
aGFzZWxsdXMgZ3JhdmlkYSBzZW1wZXIgbmlzaS4gUGVsbGVudG
VzcXVlIGNvbW1vZG8gZXJvcyBhIGVuaW0uIFN1c3BlbmRpc3Nl
IGZhdWNpYnVzLCBudW5jIGV0IHBlbGxlbnRlc3F1ZSBlZ2VzdG
FzLCBsYWN1cyBhbnRlIGNvbnZhbGxpcyB0ZWxsdXMsIHZpdGFl
IGlhY3VsaXMgbGFjdXMgZWxpdCBpZCB0b3J0b3IuIEZ1c2NlIH
ZlbCBkdWku
--- END ---";

  [Test]
  public void FormatWithTagsTest()
  {
    byte[] bytes = Encoding.UTF8.GetBytes(testString);
    string base64 = Convert.ToBase64String(bytes);

    List<string> tags80 = FormatUtils.FormatWithTags(base64);
    var actual = String.Join("\r\n", tags80);
    //Console.WriteLine(actual);
    Assert.That(actual, Is.EqualTo(expected80));

    List<string> tags50 = FormatUtils.FormatWithTags(base64, 50);
    actual = String.Join("\r\n", tags50);
    Console.WriteLine(actual);
    Assert.That(actual, Is.EqualTo(expected50));

    Assert.That(FormatUtils.RemoveTags(tags80), Is.EqualTo(base64));
    Assert.That(FormatUtils.RemoveTags(tags50), Is.EqualTo(base64));
  }

  [Test]
  public void FormatWithTagsNoContent()
  {
    Assert.That(FormatUtils.FormatWithTags(string.Empty), Is.EqualTo(new List<String>()));
  }

  [Test]
  public void RemoveTagsInvalidFormatTest()
  {
    // No BEGIN_TAG
    List<string> sut = new List<string> { FormatUtils.END_TAG };
    Assert.That(() => FormatUtils.RemoveTags(sut),Throws.ArgumentException);

    // Wrong tag order
    sut.Add(FormatUtils.BEGIN_TAG);
    Assert.That(() => FormatUtils.RemoveTags(sut), Throws.ArgumentException);

    // No END_TAG
    sut = new List<string> { FormatUtils.BEGIN_TAG};
    Assert.That(() => FormatUtils.RemoveTags(sut),Throws.ArgumentException);

    // No content between tags
    sut.Add(FormatUtils.END_TAG);
    Assert.That(FormatUtils.RemoveTags(sut), Is.EqualTo(string.Empty));
  }
}
