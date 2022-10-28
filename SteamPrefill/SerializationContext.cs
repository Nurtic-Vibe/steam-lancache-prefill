namespace SteamPrefill
{
    //TODO move to models folder
    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Default)]
    [JsonSerializable(typeof(List<uint>))]
    [JsonSerializable(typeof(Dictionary<uint, HashSet<ulong>>))]
    [JsonSerializable(typeof(Dictionary<string, SteamSpyApp>))]
    [JsonSerializable(typeof(UserLicenses))]
    internal partial class SerializationContext : JsonSerializerContext
    {
    }
}