using System.Text;
using ContainerRuntimeProbe.Model;

namespace ContainerRuntimeProbe.Rendering;

internal static class ReportSummaryRenderer
{
    public static void AppendMarkdown(StringBuilder sb, ContainerRuntimeReport report)
    {
        sb.AppendLine("## Summary");
        var summary = report.Summary ?? report.GetSummary();
        if (summary.Environment.Sections.Count == 0 && summary.Identity.Sections.Count == 0)
        {
            sb.AppendLine("- No summary facts available. Inspect the detailed sections below.");
            return;
        }

        if (summary.Environment.Sections.Count > 0)
        {
            sb.AppendLine("### Environment");
            foreach (var section in summary.Environment.Sections)
            {
                AppendEnvironmentSectionMarkdown(sb, section);
            }
        }

        if (summary.Identity.Sections.Count > 0)
        {
            sb.AppendLine("### Identity");
            foreach (var section in summary.Identity.Sections)
            {
                AppendIdentitySectionMarkdown(sb, section);
            }
        }
    }

    public static void AppendText(StringBuilder sb, ContainerRuntimeReport report)
    {
        sb.AppendLine("Summary");
        sb.AppendLine("--------");

        var summary = report.Summary ?? report.GetSummary();
        if (summary.Environment.Sections.Count == 0 && summary.Identity.Sections.Count == 0)
        {
            sb.AppendLine("- No summary facts available. Inspect the details below.");
            sb.AppendLine();
            return;
        }

        if (summary.Environment.Sections.Count > 0)
        {
            sb.AppendLine("Environment");
            foreach (var section in summary.Environment.Sections)
            {
                AppendEnvironmentSectionText(sb, section);
            }

            sb.AppendLine();
        }

        if (summary.Identity.Sections.Count > 0)
        {
            sb.AppendLine("Identity");
            foreach (var section in summary.Identity.Sections)
            {
                AppendIdentitySectionText(sb, section);
            }

            sb.AppendLine();
        }
    }

    private static void AppendEnvironmentSectionMarkdown(StringBuilder sb, EnvironmentSummarySection section)
    {
        sb.AppendLine($"#### {section.Title}");
        sb.AppendLine("| Label | Value |");
        sb.AppendLine("| --- | --- |");
        foreach (var fact in section.Facts)
        {
            sb.AppendLine($"| {EscapeMarkdownTableCell(fact.Label)} | {EscapeMarkdownTableCell(fact.Value)} |");
        }
    }

    private static void AppendIdentitySectionMarkdown(StringBuilder sb, IdentitySummarySection section)
    {
        sb.AppendLine($"#### {section.Title}");
        sb.AppendLine("| Label | Value | Level | Usage |");
        sb.AppendLine("| --- | --- | --- | --- |");
        foreach (var fact in section.Facts)
        {
            sb.AppendLine($"| {EscapeMarkdownTableCell(fact.Label)} | {EscapeMarkdownTableCell(fact.Value)} | {FormatLevel(fact.Level)} | {fact.Usage} |");
        }
    }

    private static void AppendEnvironmentSectionText(StringBuilder sb, EnvironmentSummarySection section)
    {
        sb.AppendLine(section.Title);
        foreach (var fact in section.Facts)
        {
            sb.AppendLine($"  {fact.Label.PadRight(14)} : {fact.Value}");
        }
    }

    private static void AppendIdentitySectionText(StringBuilder sb, IdentitySummarySection section)
    {
        sb.AppendLine(section.Title);
        foreach (var fact in section.Facts)
        {
            sb.AppendLine($"  {fact.Label.PadRight(22)} : {fact.Value}  [{FormatLevel(fact.Level)}] [{fact.Usage}]");
        }
    }

    private static string EscapeMarkdownTableCell(string value)
        => value.Replace("|", "\\|", StringComparison.Ordinal);

    private static string FormatLevel(int? level)
        => level is null || level <= 0 ? "-" : $"L{level}";
}