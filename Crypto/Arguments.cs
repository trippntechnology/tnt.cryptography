using TNT.ArgumentParser;

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

		protected EnumArgument<ActionEnum> ActionArg => this[ACTION] as EnumArgument<ActionEnum>;
		protected FileArgument OutputFileArg => this[OUTPUT] as FileArgument;
		protected FileArgument InputFileArg => this[INPUT_FILE] as FileArgument;
		protected FileArgument KeyFileArg => this[KEY_FILE] as FileArgument;


		public ActionEnum Action => ActionArg.Value;
		public string OutputFile => OutputFileArg.Value;
		public string KeyFile => KeyFileArg.Value;
		public string InputFile => InputFileArg.Value;

		public Arguments()
		{
			this.Add(new FileArgument(INPUT_FILE, INPUT_File_DESCRIPTION) { MustExist = true });
			this.Add(new FileArgument(KEY_FILE, KEY_FILE_DESCRIPTION) { MustExist = true });
			this.Add(new FileArgument(OUTPUT, OUTPUT_DESCRIPTION, true));
			this.Add(new EnumArgument<ActionEnum>(ACTION, ACTION_DESCRIPTION, true));
		}

		protected override void SetRequiredDependencies()
		{
			switch ((this[ACTION] as EnumArgument<ActionEnum>).Value)
			{
				case ActionEnum.ENCRYPT:
				case ActionEnum.DECRYPT:
					InputFileArg.IsRequired = true;
					InputFileArg.MustExist = true;
					KeyFileArg.IsRequired = true;

					break;
				case ActionEnum.KEYGEN:
					break;
			}
		}
	}
}
