using System.Security.Cryptography;
using System.Text;

namespace HashGuardScanner;

internal sealed record HashGuardFirewallRule(string Name, string ApplicationPath, bool Inbound, bool Enabled);

internal sealed record FirewallProfileState(bool AllActiveProfilesEnabled, string Description);

/// <summary>
/// Per-program block rules in Windows Firewall, through its COM API (HNetCfg.FwPolicy2).
///
/// Every rule HashGuard creates carries <see cref="Grouping"/> = "HashGuard"; listing,
/// unblocking and "remove all" only ever touch rules in that group, so the user's own
/// rules and Windows' built-in rules are never changed. Writing rules needs elevation.
/// </summary>
internal static class FirewallRules
{
    public const string Grouping = "HashGuard";
    private const int DirectionIn = 1;
    private const int DirectionOut = 2;
    private const int ActionBlock = 0;
    private const int AllProfiles = 0x7FFFFFFF;

    /// <summary>
    /// Unique, readable rule name: "HashGuard block: app.exe (1a2b3c4d)" — the suffix is a hash of
    /// the normalized path so two programs with the same file name get different rules.
    /// </summary>
    public static string RuleName(string applicationPath, bool inbound) =>
        $"HashGuard block{(inbound ? " inbound" : "")}: {NetworkActivityTracker.DisplayName(NormalizePath(applicationPath))} ({ShortPathHash(applicationPath)})";

    public static string ShortPathHash(string applicationPath)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(NormalizePath(applicationPath).ToUpperInvariant()));
        return Convert.ToHexString(bytes, 0, 4).ToLowerInvariant();
    }

    /// <summary>Trims quotes/spaces, uses backslashes and expands %VARS% (rules may store them).</summary>
    public static string NormalizePath(string? applicationPath)
    {
        var path = (applicationPath ?? "").Trim().Trim('"').Trim();
        path = Environment.ExpandEnvironmentVariables(path);
        return path.Replace('/', '\\');
    }

    public static bool PathsEqual(string? left, string? right) =>
        string.Equals(NormalizePath(left), NormalizePath(right), StringComparison.OrdinalIgnoreCase);

    /// <summary>Paths that should get an extra warning before blocking (Windows parts, HashGuard).</summary>
    public static bool IsSensitivePath(string applicationPath, string windowsDirectory, string hashGuardPath)
    {
        var path = NormalizePath(applicationPath);
        if (string.Equals(path, "System", StringComparison.OrdinalIgnoreCase) || PathsEqual(path, hashGuardPath))
        {
            return true;
        }

        var windows = NormalizePath(windowsDirectory).TrimEnd('\\');
        return windows.Length > 0 && path.StartsWith(windows + "\\", StringComparison.OrdinalIgnoreCase);
    }

    public static void Block(string applicationPath, bool alsoInbound)
    {
        var path = NormalizePath(applicationPath);
        var policy = CreatePolicy();
        // Replace any earlier HashGuard rule for this program (however its path was cased),
        // so blocking twice, or switching inbound on or off, never leaves duplicates.
        dynamic com = policy;
        foreach (var name in ReadRules(policy).Where(rule => PathsEqual(rule.ApplicationPath, path)).Select(rule => rule.Name).ToList())
        {
            com.Rules.Remove(name);
        }

        AddBlockRule(policy, path, inbound: false);
        if (alsoInbound)
        {
            AddBlockRule(policy, path, inbound: true);
        }
    }

    /// <summary>Removes HashGuard's rules for the program; returns how many were removed.</summary>
    public static int Unblock(string applicationPath)
    {
        var policy = CreatePolicy();
        dynamic com = policy;
        var names = ReadRules(policy)
            .Where(rule => PathsEqual(rule.ApplicationPath, applicationPath))
            .Select(rule => rule.Name)
            .ToList();
        foreach (var name in names)
        {
            com.Rules.Remove(name);
        }

        return names.Count;
    }

    public static List<HashGuardFirewallRule> ListHashGuardRules() => ReadRules(CreatePolicy());

    /// <summary>The "undo everything" button: removes every rule in the HashGuard group.</summary>
    public static int RemoveAllHashGuardRules()
    {
        var policy = CreatePolicy();
        dynamic com = policy;
        var names = ReadRules(policy).Select(rule => rule.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var name in names)
        {
            com.Rules.Remove(name);
        }

        return names.Count;
    }

    /// <summary>Whether Windows Firewall is on for every active profile (domain/private/public).</summary>
    public static FirewallProfileState GetProfileState()
    {
        try
        {
            dynamic policy = CreatePolicy();
            int current = policy.CurrentProfileTypes;
            var off = new List<string>();
            foreach (var (bit, name) in new[] { (1, "Domain"), (2, "Private"), (4, "Public") })
            {
                if ((current & bit) != 0 && !(bool)policy.FirewallEnabled[bit])
                {
                    off.Add(name);
                }
            }

            return off.Count == 0
                ? new FirewallProfileState(true, "Windows Firewall is on.")
                : new FirewallProfileState(false, $"Windows Firewall is off for the active {string.Join("/", off)} network, so blocks won't take effect. Another firewall may be managing this PC.");
        }
        catch (Exception ex)
        {
            return new FirewallProfileState(false, $"Windows Firewall could not be read ({ex.Message}). Blocks may not take effect.");
        }
    }

    private static void AddBlockRule(object policyObject, string path, bool inbound)
    {
        dynamic policy = policyObject;
        var name = RuleName(path, inbound);
        try
        {
            policy.Rules.Remove(name);
        }
        catch
        {
            // Not there yet.
        }

        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule") ?? throw new InvalidOperationException("Windows Firewall is not available.");
        dynamic rule = Activator.CreateInstance(ruleType) ?? throw new InvalidOperationException("Could not create a Windows Firewall rule.");
        rule.Name = name;
        rule.Description = $"Added by HashGuard Network Monitor on {DateTime.Now:g}. Remove it in HashGuard (Unblock) or here.";
        rule.ApplicationName = path;
        rule.Action = ActionBlock;
        rule.Direction = inbound ? DirectionIn : DirectionOut;
        rule.Enabled = true;
        rule.Grouping = Grouping;
        rule.Profiles = AllProfiles;
        rule.InterfaceTypes = "All";
        policy.Rules.Add(rule);
    }

    private static List<HashGuardFirewallRule> ReadRules(object policyObject)
    {
        dynamic policy = policyObject;
        var rules = new List<HashGuardFirewallRule>();
        foreach (dynamic rule in policy.Rules)
        {
            string? grouping = rule.Grouping;
            if (!string.Equals(grouping, Grouping, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string name = rule.Name ?? "";
            string application = rule.ApplicationName ?? "";
            int direction = rule.Direction;
            bool enabled = rule.Enabled;
            rules.Add(new HashGuardFirewallRule(name, NormalizePath(application), direction == DirectionIn, enabled));
        }

        return rules;
    }

    private static object CreatePolicy()
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2") ?? throw new InvalidOperationException("Windows Firewall is not available.");
        return Activator.CreateInstance(policyType) ?? throw new InvalidOperationException("Could not open Windows Firewall.");
    }
}
