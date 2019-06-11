using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TNT.Cryptography;

namespace KeyGen
{
	class Program
	{
		static void Main(string[] args)
		{
			var parms = new Parameters();

			if (!parms.ParseArgs(args))
			{
				return;
			}

			var asymmetric = new Asymmetric();

			asymmetric.PrivateKey.Save(parms.PrivateFileName);
			asymmetric.PublicKey.Save(parms.PublicFileName);
		}
	}
}
