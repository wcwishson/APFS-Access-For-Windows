using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace ApfsAccess.StandardMount;

// Uses the existing OS alternative-port cmdlets. Credentials travel only through
// inherited stdin; neither command lines nor files contain the ephemeral secret.
public sealed class WindowsLoopbackMapping : IStandardMappingController
{
    private const string Script = """
        $ErrorActionPreference='Stop'
        $stage='Input'
        try {
          $r=[Console]::ReadLine()|ConvertFrom-Json
          $server=[Net.IPAddress]::Parse($r.ServerAddress)
          if($server.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $server.GetAddressBytes()[0] -ne 127 -or $server.ToString() -cne $r.ServerAddress){throw 'scope'}
          $prefix='\\'+$r.ServerAddress+'\'
          if(!$r.RemotePath.StartsWith($prefix,[StringComparison]::Ordinal) -or $r.RemotePath.Substring($prefix.Length) -notmatch '^APFS_[A-Za-z0-9_-]+$'){throw 'scope'}
          function Identity($m){
            @([string]$m.RemotePath,[string]$m.LocalPath,[int]$m.TcpPort,[int]$m.TransportType,[bool]$m.GlobalMapping,[bool]$m.RequireIntegrity,[bool]$m.RequirePrivacy)|ConvertTo-Json -Compress
          }
          function OwnedConnection($r,$allowMissing){
            $share=($r.RemotePath -split '\\')[-1]
            $c=@(Get-SmbConnection -ErrorAction Stop|Where-Object {$_.ServerName -eq $r.ServerAddress -and $_.ShareName -ceq $share})
            if($allowMissing -and $c.Count -eq 0){return}
            if($c.Count -ne 1 -or !$c[0].Signed -or $c[0].Credential -ine ('APFSSTANDARD\'+$r.UserName)){throw 'connection'}
          }
          $stage='QueryMapping'
          $m=@(Get-SmbMapping -ErrorAction Stop|Where-Object {$_.RemotePath -ieq $r.RemotePath})
          if($r.Action -eq 'Map') {
            if($m.Count -ne 0 -or !(Get-Command New-SmbMapping).Parameters.ContainsKey('TcpPort')){throw 'mapping'}
            if($r.Password.Length -ne 44 -or $r.UserName -notmatch '^apfs_[a-f0-9]{32}$' -or $r.Port -le 1024 -or $r.Port -gt 65535){throw 'input'}
            $stage='CreateMapping'
            New-SmbMapping -RemotePath $r.RemotePath -TransportType TCP -TcpPort $r.Port -UserName ('APFSSTANDARD\'+$r.UserName) -Password $r.Password -Persistent $false -RequireIntegrity $true -ErrorAction Stop|Out-Null
            $r.Password=$null
            $stage='ObserveMapping'
            $m=@(Get-SmbMapping -RemotePath $r.RemotePath -ErrorAction Stop)
            if($m.Count -ne 1 -or $m[0].LocalPath -or $m[0].GlobalMapping -or !$m[0].RequireIntegrity -or $m[0].TcpPort -ne $r.Port){throw 'observe'}
            @{state='created';identity=(Identity $m[0]);remotePath=$r.RemotePath}|ConvertTo-Json -Compress
          } elseif($r.Action -eq 'Probe') {
            $stage='ProbeMapping'
            if($m.Count -ne 1 -or (Identity $m[0]) -cne $r.Identity){throw 'foreign'}
            if(![IO.Directory]::Exists($r.RemotePath+'\')){throw 'probe'}
            OwnedConnection $r $false
            '{"state":"connected"}'
          } elseif($r.Action -eq 'Remove') {
            $stage='RemoveMapping'
            if($m.Count -eq 0){'{"state":"absent"}';exit 0}
            if($m.Count -ne 1 -or (Identity $m[0]) -cne $r.Identity){throw 'foreign'}
            OwnedConnection $r $true
            Remove-SmbMapping -RemotePath $r.RemotePath -Confirm:$false -ErrorAction Stop
            if(@(Get-SmbMapping -ErrorAction Stop|Where-Object {$_.RemotePath -ieq $r.RemotePath}).Count -ne 0){throw 'reserved'}
            '{"state":"absent"}'
          } else {throw 'action'}
        } catch {
          $windowsError=0
          if($_.FullyQualifiedErrorId -match 'Windows System Error ([0-9]{1,10})'){[void][int]::TryParse($Matches[1],[ref]$windowsError)}
          @{state='refused';stage=$stage;code=[int]$_.Exception.HResult;windowsError=$windowsError}|ConvertTo-Json -Compress;exit 1
        }
        """;
    private readonly SemaphoreSlim gate = new(1, 1);
    private Process? retainedCommand;
    private Task<string>? retainedOutput, retainedError;
    private Action<JsonElement>? retainedObservation;
    private readonly Func<object, CancellationToken, ValueTask<JsonElement>>? command;
    public WindowsLoopbackMapping() { }
    internal WindowsLoopbackMapping(Func<object, CancellationToken, ValueTask<JsonElement>> command) => this.command = command;

    private static async Task<string> ReadBoundedAsync(StreamReader reader)
    {
        var result = new StringBuilder(); var buffer = new char[1024]; var overflow = false;
        int count;
        while ((count = await reader.ReadAsync(buffer).ConfigureAwait(false)) != 0)
        {
            if (result.Length + count > 8192) overflow = true;
            if (!overflow) result.Append(buffer, 0, count);
        }
        if (overflow) throw new IOException("Mapping command output exceeded its bound.");
        return result.ToString();
    }

    private async ValueTask<JsonElement?> CompleteRetainedAsync(bool ignoreFailure)
    {
        try
        {
            var outputs = await Task.WhenAll(retainedOutput!, retainedError!).ConfigureAwait(false);
            using var document = JsonDocument.Parse(outputs[0]);
            var result = document.RootElement.Clone();
            if (retainedCommand!.ExitCode != 0)
            {
                var stage = result.TryGetProperty("stage", out var observed) ? observed.GetString() : null;
                var closedStage = stage is "Input" or "QueryMapping" or "CreateMapping" or "ObserveMapping" or "ProbeMapping" or "RemoveMapping" ? stage : "Unknown";
                var code = result.TryGetProperty("code", out var number) && number.TryGetInt32(out var value) ? value : 0;
                var windowsError = result.TryGetProperty("windowsError", out var native) && native.TryGetInt32(out var nativeValue) ? nativeValue : 0;
                throw new IOException($"Owned mapping command refused at {closedStage} (HRESULT {code}, Windows {windowsError}).");
            }
            retainedObservation?.Invoke(result);
            return result;
        }
        catch (Exception e) when (ignoreFailure && e is IOException or JsonException) { return null; }
        finally
        {
            retainedCommand!.Dispose(); retainedCommand = null;
            retainedOutput = retainedError = null; retainedObservation = null;
        }
    }

    private async ValueTask<JsonElement> ExecuteAsync(Func<object> input, CancellationToken token, Action<JsonElement>? observe = null)
    {
        if (command is not null)
        {
            var result = await command(input(), token).ConfigureAwait(false); observe?.Invoke(result); return result;
        }
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        await gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (retainedCommand is not null)
            {
                if (!retainedCommand.HasExited) throw new IOException("An owned mapping command remains reserved.");
                await CompleteRetainedAsync(ignoreFailure: true).ConfigureAwait(false);
            }
            var binary = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            var psi = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(Script)) }) psi.ArgumentList.Add(arg);
            retainedCommand = Process.Start(psi) ?? throw new IOException("Mapping command did not start.");
            retainedObservation = observe;
            retainedOutput = ReadBoundedAsync(retainedCommand.StandardOutput);
            retainedError = ReadBoundedAsync(retainedCommand.StandardError);
            try { await retainedCommand.StandardInput.WriteLineAsync(JsonSerializer.Serialize(input()).AsMemory(), token).ConfigureAwait(false); }
            finally { retainedCommand.StandardInput.Close(); }
            await retainedCommand.WaitForExitAsync(token).ConfigureAwait(false);
            return (await CompleteRetainedAsync(ignoreFailure: false).ConfigureAwait(false))!.Value;
        }
        finally
        {
            if (retainedCommand is { HasExited: true })
            {
                await CompleteRetainedAsync(ignoreFailure: true).ConfigureAwait(false);
            }
            gate.Release();
        }
    }
    public IStandardMappingLease Reserve(StandardShareOptions options)
    {
        if (!options.IsValid || !options.ShareName.StartsWith("APFS_", StringComparison.Ordinal)) throw new ArgumentException("Use a fresh explicit APFS loopback share.");
        return new Lease(this, options);
    }
    private sealed class Lease(WindowsLoopbackMapping owner, StandardShareOptions options) : IStandardMappingLease
    {
        private string? identity;
        private string? userName;
        private bool attempted;
        public string RemotePath => options.RemotePath;
        private void ObserveCreated(JsonElement result)
        {
            if (result.GetProperty("state").GetString() != "created" || result.GetProperty("remotePath").GetString() != options.RemotePath ||
                result.GetProperty("identity").GetString() is not { Length: > 0 and <= 4096 } observed || identity is not null && identity != observed)
                throw new IOException("Mapping creation observation failed.");
            identity = observed;
        }
        public async ValueTask ConnectAsync(StandardSmbCredential credential, CancellationToken cancellationToken)
        {
            if (attempted) throw new InvalidOperationException("Mapping attempt already owns this reservation.");
            attempted = true;
            userName = credential.UserName;
            await owner.ExecuteAsync(() => new { Action = "Map", options.RemotePath, ServerAddress = options.LoopbackAddress, Port = options.TcpPort, credential.UserName,
                Password = credential.RequirePassword() }, cancellationToken, ObserveCreated).ConfigureAwait(false);
            var connected = await owner.ExecuteAsync(() => new { Action = "Probe", RemotePath, ServerAddress = options.LoopbackAddress, Identity = identity, UserName = userName }, cancellationToken).ConfigureAwait(false);
            if (connected.GetProperty("state").GetString() != "connected") throw new IOException("Mapping connection probe failed.");
        }
        public async ValueTask<bool> RemoveOwnedMappingAsync(CancellationToken cancellationToken)
        {
            // An unobserved Map outcome can only prove absence; it cannot authorize removal.
            var result = await owner.ExecuteAsync(() => new { Action = "Remove", RemotePath, ServerAddress = options.LoopbackAddress, Identity = identity ?? "", UserName = userName ?? "" }, cancellationToken).ConfigureAwait(false);
            return result.GetProperty("state").GetString() == "absent";
        }
    }
}
