namespace ContainerRuntimeProbe.Internal;

internal static class PlatformSignalMatching
{
    internal static IReadOnlyList<string> FindSignalsFromEnvironmentKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return [];
        }

        var normalized = key.Replace('_', '-');
        var compact = key.Replace("_", string.Empty, StringComparison.Ordinal);
        return FindSignals(normalized, includeGenericIndustrial: false)
            .Concat(FindSignals(compact, includeGenericIndustrial: false))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static readonly string[] SubstringSignals =
    [
        "industrial-edge",
        "industrialedge",
        "siemens",
        "iotedge",
        "industrial"
    ];

    private static readonly string[] TokenOnlySignals =
    [
        "ie",
        "iem",
        "ied"
    ];

    internal static IReadOnlyList<string> FindSignals(string? value, bool includeGenericIndustrial = false)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var matches = new List<string>();
        foreach (var signal in SubstringSignals)
        {
            if (!includeGenericIndustrial && string.Equals(signal, "industrial", StringComparison.Ordinal))
            {
                continue;
            }

            if (value.Contains(signal, StringComparison.OrdinalIgnoreCase))
            {
                matches.Add(signal);
            }
        }

        foreach (var signal in TokenOnlySignals)
        {
            if (ContainsToken(value, signal))
            {
                matches.Add(signal);
            }
        }

        return matches.Distinct(StringComparer.Ordinal).ToArray();
    }

    internal static bool ContainsToken(string? value, string token)
    {
        if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        var comparison = StringComparison.OrdinalIgnoreCase;
        var index = 0;
        while (index <= value.Length - token.Length)
        {
            index = value.IndexOf(token, index, comparison);
            if (index < 0)
            {
                return false;
            }

            var beforeBoundary = index == 0 || IsBoundary(value[index - 1]);
            var afterIndex = index + token.Length;
            var afterBoundary = afterIndex == value.Length || IsBoundary(value[afterIndex]);
            if (beforeBoundary && afterBoundary)
            {
                return true;
            }

            index++;
        }

        return false;
    }

    private static bool IsBoundary(char character)
        => char.IsWhiteSpace(character)
           || character is '/' or '-' or '_' or '.' or ':' or '=';
}