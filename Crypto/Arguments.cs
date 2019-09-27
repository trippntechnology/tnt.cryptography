using TNT.ArgumentParser;
using TNT.Utilities;

namespace Crypto
{
	class Arguments : ArgumentParser
	{
		const string ACTION = "a";
		const string ACTION_DESCRIPTION = "Action to perform";

		const string OUTPUT = "o";
		const string OUTPUT_DESCRIPTION = "File where output will be written";

		const string KEY_FILE = "k";
		const string KEY_FILE_DESCRIPTION = "File containing symmetric key";

		const string INPUT_FILE = "i";
		const string INPUT_File_DESCRIPTION = "File containing plain or cypher text";

		const string PASSWORD = "p";
		const string PASSWORD_DESCRIPTION = "Key password";

		const string IV = "iv";
		const string IV_DESCRIPTION = "Initialization vector. Must be 16 ASCII characters";

		const string FORMAT = "f";
		const string FORMAT_DESCRIPTION = "Format the encrypted output";

		const string SALT = "s";
		const string SALT_DESCRIPTION = "Salt applied to the key";

		protected EnumArgument<ActionEnum> ActionArg => this[ACTION] as EnumArgument<ActionEnum>;
		protected FileArgument OutputFileArg => this[OUTPUT] as FileArgument;
		protected FileArgument InputFileArg => this[INPUT_FILE] as FileArgument;
		protected FileArgument KeyFileArg => this[KEY_FILE] as FileArgument;
		protected StringArgument PasswordKeyArg => this[PASSWORD] as StringArgument;
		protected StringArgument InitializationVector => this[IV] as StringArgument;
		protected FlagArgument FormatArg => this[FORMAT] as FlagArgument;
		protected StringArgument SaltArg => this[SALT] as StringArgument;

		public ActionEnum Action => ActionArg.Value;
		public string OutputFile => OutputFileArg.Value;
		public string KeyFile => KeyFileArg.Value;
		public string InputFile => InputFileArg.Value;
		public string PasswordKey => PasswordKeyArg.Value;
		public string InitVector => InitializationVector.Value;
		public bool Format => FormatArg.Value;
		public string Salt => SaltArg.Value;

		public Arguments()
		{
			this.Add(new FileArgument(INPUT_FILE, INPUT_File_DESCRIPTION) { MustExist = true });
			this.Add(new FileArgument(KEY_FILE, KEY_FILE_DESCRIPTION) { MustExist = true });
			this.Add(new FileArgument(OUTPUT, OUTPUT_DESCRIPTION, true));
			this.Add(new EnumArgument<ActionEnum>(ACTION, ACTION_DESCRIPTION, true));
			this.Add(new StringArgument(PASSWORD, PASSWORD_DESCRIPTION));
			this.Add(new StringArgument(IV, IV_DESCRIPTION));
			this.Add(new FlagArgument(FORMAT, FORMAT_DESCRIPTION));
			this.Add(new StringArgument(SALT, SALT_DESCRIPTION, defaultValue: string.Empty));
		}

		protected override void SetRequiredDependencies()
		{
			switch ((this[ACTION] as EnumArgument<ActionEnum>).Value)
			{
				case ActionEnum.ENCRYPT:
					InputFileArg.IsRequired = true;
					InputFileArg.MustExist = true;
					KeyFileArg.IsRequired = true;
					InitializationVector.IsRequired = true;
					break;
				case ActionEnum.DECRYPT:
					InputFileArg.IsRequired = true;
					InputFileArg.MustExist = true;
					KeyFileArg.IsRequired = true;
					break;
				case ActionEnum.KEYGEN:
					PasswordKeyArg.IsRequired = true;
					break;
			}
		}
	}
}
