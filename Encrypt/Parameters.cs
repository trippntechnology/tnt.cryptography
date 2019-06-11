using TNT.Utilities.Console;

namespace Encrypt
{
	class Parameters : TNT.Utilities.Console.Parameters
	{
		const string KEY_FILE = "k";
		const string INPUT_FILE = "i";
		const string OUTPUT_FILE = "o";

		public string Key { get { return (this[KEY_FILE] as FileParameter).Value; } }
		public string PlainTextFile { get { return (this[INPUT_FILE] as FileParameter).Value; } }
		public string CipherFile { get { return (this[OUTPUT_FILE] as FileParameter).Value; } }

		public Parameters()
		{
			this.Add(new FileParameter(KEY_FILE, "File containing the encryption key", true) { MustExist = true });
			this.Add(new FileParameter(INPUT_FILE, "File containing the plain text to encrypt", true) { MustExist = true });
			this.Add(new FileParameter(OUTPUT_FILE, "Output file name that will store the encrypted content", true));
		}
	}
}
