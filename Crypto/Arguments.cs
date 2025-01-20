using TNT.ArgumentParser;

namespace Crypto
{
  class Arguments : ArgumentParser
  {
    const string ACTION = "a";
    const string ACTION_DESCRIPTION = "Action to perform";

    const string OUTPUT = "o";
    const string OUTPUT_DESCRIPTION = "File where output will be written";

    const string INPUT_FILE = "i";
    const string INPUT_File_DESCRIPTION = "File containing plain or cipher text";

    const string PASSWORD = "p";
    const string PASSWORD_DESCRIPTION = "Key password";

    const string FORMAT = "f";
    const string FORMAT_DESCRIPTION = "Format the encrypted output";

    const string CIPHER_ATTRIBUTE_FILE = "caf";
    const string CIPHER_ATTRIBUTE_DESCRIPTION_FILE = "File containing the cipher attribute used by the symmetric cipher";

    protected EnumArgument<ActionEnum> ActionArg = new EnumArgument<ActionEnum>(ACTION, ACTION_DESCRIPTION, true);
    protected FileArgument InputFileArg = new FileArgument(INPUT_FILE, INPUT_File_DESCRIPTION, mustExist: true);
    protected FileArgument OutputFileArg = new FileArgument(OUTPUT, OUTPUT_DESCRIPTION, true);
    protected FlagArgument FormatArg = new FlagArgument(FORMAT, FORMAT_DESCRIPTION);
    protected StringArgument PasswordKeyArg = new StringArgument(PASSWORD, PASSWORD_DESCRIPTION);
    protected FileArgument CAFileArg = new FileArgument(CIPHER_ATTRIBUTE_FILE, CIPHER_ATTRIBUTE_DESCRIPTION_FILE, mustExist: true);

    public ActionEnum Action => ActionArg.Value;
    public string? OutputFile => OutputFileArg.Value;
    public string? InputFile => InputFileArg.Value;
    public string? PasswordKey => PasswordKeyArg.Value;
    public bool Format => FormatArg.Value;
    public string? CAFile => CAFileArg.Value;

    public Arguments()
    {
      this.Add(ActionArg);
      this.Add(InputFileArg);
      this.Add(OutputFileArg);
      this.Add(FormatArg);
      this.Add(PasswordKeyArg);
      this.Add(CAFileArg);
    }

    protected override void SetRequiredDependencies()
    {
      switch (ActionArg.Value)
      {
        case ActionEnum.ENCRYPT:
        case ActionEnum.DECRYPT:
          InputFileArg.IsRequired = true;
          InputFileArg.MustExist = true;
          CAFileArg.IsRequired = true;
          break;
        case ActionEnum.GEN_CA:
          PasswordKeyArg.IsRequired = true;
          break;
      }
    }
  }
}
