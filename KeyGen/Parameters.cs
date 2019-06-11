using TNT.Utilities.Console;

namespace KeyGen
{
	class Parameters : TNT.Utilities.Console.Parameters
	{
		const string PRIVATE_KEY_NAME = "sk";
		const string PUBLIC_KEY_NAME = "pk";

		public string PrivateFileName { get { return (this[PRIVATE_KEY_NAME] as FileParameter).Value; } }

		public string PublicFileName { get { return (this[PUBLIC_KEY_NAME] as FileParameter).Value; } }

		public Parameters()
		{
			this.Add(new FileParameter(PRIVATE_KEY_NAME, "Private key file name", true));
			this.Add(new FileParameter(PUBLIC_KEY_NAME, "Public key file name", true));
		}
	}
}
