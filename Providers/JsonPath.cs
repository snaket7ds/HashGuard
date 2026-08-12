using System.Text.Json;

namespace HashGuardScanner;

internal static class JsonPath
{
    public static JsonElement ReadElement(JsonElement root, params string[] path)
    {
        var current = root;
        foreach (var segment in path)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out current))
            {
                return default;
            }
        }

        return current;
    }

    public static int ReadInt(JsonElement root, string property)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(property, out var value))
        {
            return 0;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt32(out var number) => number,
            JsonValueKind.String when int.TryParse(value.GetString(), out var parsed) => parsed,
            _ => 0,
        };
    }

    public static string? ReadString(JsonElement root, params string[] path)
    {
        var value = ReadElement(root, path);
        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}
