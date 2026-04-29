using System.Text.Json;
using System.Text.Json.Serialization;
using ContainerRuntimeProbe.Internal;

namespace ContainerRuntimeProbe.Model;

internal sealed class KernelCompilerInfoJsonConverter : JsonConverter<KernelCompilerInfo>
{
    public override KernelCompilerInfo? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType == JsonTokenType.String)
        {
            return CreateFromRaw(reader.GetString());
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Unexpected token {reader.TokenType} for {nameof(KernelCompilerInfo)}.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        var raw = GetString(root, nameof(KernelCompilerInfo.Raw));
            
        return new KernelCompilerInfo(
            GetString(root, nameof(KernelCompilerInfo.Name)),
            GetString(root, nameof(KernelCompilerInfo.Version)),
            raw,
            GetString(root, nameof(KernelCompilerInfo.DistributionHint)),
            GetString(root, nameof(KernelCompilerInfo.DistributionVersionHint)))
            ?? CreateFromRaw(raw);
    }

    public override void Write(Utf8JsonWriter writer, KernelCompilerInfo value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStartObject();
        WriteString(writer, nameof(KernelCompilerInfo.Name), value.Name);
        WriteString(writer, nameof(KernelCompilerInfo.Version), value.Version);
        WriteString(writer, nameof(KernelCompilerInfo.Raw), value.Raw);
        WriteString(writer, nameof(KernelCompilerInfo.DistributionHint), value.DistributionHint);
        WriteString(writer, nameof(KernelCompilerInfo.DistributionVersionHint), value.DistributionVersionHint);
        writer.WriteEndObject();
    }

    private static KernelCompilerInfo? CreateFromRaw(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var parsed = HostParsing.ParseKernelCompiler(raw);
        return new KernelCompilerInfo(
            parsed?.Name,
            parsed?.Version,
            raw,
            parsed?.DistributionHint,
            parsed?.DistributionVersionHint);
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.Null ? null : value.GetString();
    }

    private static void WriteString(Utf8JsonWriter writer, string propertyName, string? value)
    {
        if (value is null)
        {
            writer.WriteNull(propertyName);
            return;
        }

        writer.WriteString(propertyName, value);
    }
}