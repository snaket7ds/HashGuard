namespace HashGuardScanner;

/// <summary>
/// Process-wide non-reentrant gate so full scans, process monitoring, and idle file
/// scans do not stack on top of each other.
/// </summary>
internal sealed class ScanGate
{
    private int entered;

    public bool IsBusy => Volatile.Read(ref entered) != 0;

    /// <summary>Returns true if this caller now owns the gate.</summary>
    public bool TryEnter() => Interlocked.CompareExchange(ref entered, 1, 0) == 0;

    public void Exit() => Interlocked.Exchange(ref entered, 0);

    public ScanGateScope? TryEnterScope() => TryEnter() ? new ScanGateScope(this) : null;
}

internal readonly struct ScanGateScope : IDisposable
{
    private readonly ScanGate gate;

    public ScanGateScope(ScanGate gate) => this.gate = gate;

    public void Dispose() => gate.Exit();
}
