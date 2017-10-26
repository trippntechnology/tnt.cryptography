using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;

namespace TNT.Cryptography.Extension
{
	/// <summary>
	/// Represents a CrlDistributionPoints <see cref="Extension"/>
	/// </summary>
	public class CrlDistributionPoints : Extension
	{
		CrlDistPoint X509CrlDistPoint = null;

		/// <summary>
		/// The CrlDistributionPoints OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.DerObjectIdentifier OID { get { return X509Extensions.CrlDistributionPoints; } }

		/// <summary>
		/// Value associated with the CrlDistributionPoints OID
		/// </summary>
		public override Org.BouncyCastle.Asn1.X509.X509Extension Value { get { return new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(this.X509CrlDistPoint)); } }

		/// <summary>
		/// Initializes the CrlDistributionPoints with a <see cref="List{Uri}"/> of <see cref="Uri"/>
		/// </summary>
		/// <param name="uris"><see cref="List{T}"/> of <see cref="Uri"/></param>
		public CrlDistributionPoints(List<Uri> uris)
		{
			List<DistributionPoint> distributionPoints = new List<DistributionPoint>();

			foreach (Uri uri in uris)
			{
				GeneralNames gnUri = new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, uri.ToString()));
				distributionPoints.Add(new DistributionPoint(new DistributionPointName(gnUri), null, null));
			}

			this.X509CrlDistPoint = new CrlDistPoint(distributionPoints.ToArray());
		}
	}
}
