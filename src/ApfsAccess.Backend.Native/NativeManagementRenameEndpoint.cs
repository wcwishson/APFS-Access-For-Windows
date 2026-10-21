using System.Globalization;
using System.Security.Cryptography;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IManagementRenameKeeper
{
    public async Task<ManagementKeeperRenameResult> RenameVolumeAsync(
        ManagementKeeperRenameRequest request,CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        using var operation=AcquireLifecycleOperationLease();
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken,_disposeCts.Token);
        try
        {
            if(!_options.EnableImageManagementMutations)throw new IOException("ImageManagementMutationsDisabled");
            if(_options.ManagementJournalRoot is not { } root||!string.Equals(root,request.JournalRoot,StringComparison.OrdinalIgnoreCase))
                throw new IOException("ManagementRenameStableRootMismatch");
            NativeApfsVolumeRename.ValidateRequest(new(request.ImagePath,request.ContainerUuid,request.VolumeUuid,
                request.VolumeObjectId,request.PreimageXid,request.NewLabel,root));
            await _discoveryGate.WaitAsync(linked.Token).ConfigureAwait(false);
            try
            {
                await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
                try{return await Task.Run(()=>RenameRegisteredImage_NoLock(request,linked.Token),linked.Token).ConfigureAwait(false);}
                finally{_gate.Release();}
            }
            finally{_discoveryGate.Release();}
        }
        catch(ArgumentException error){return new(false,0,ManagementKeeperCodes.InvalidRequest,error.Message);}
        catch(IOException error)when(error.Message=="ManagementRenamePreimageChanged")
        {return new(false,0,ManagementKeeperCodes.StalePreimage,error.Message);}
        catch(IOException error)when(error is not NativeRenameExitException)
        {return new(false,0,ManagementKeeperCodes.Refused,error.Message);}
        catch(UnauthorizedAccessException error){return new(false,0,ManagementKeeperCodes.Refused,error.Message);}
    }

    private ManagementKeeperRenameResult RenameRegisteredImage_NoLock(ManagementKeeperRenameRequest request,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        RequireManagementQuotaOwnerAbsence_NoLock();
        RequireOrdinaryImageRegistrationsConfiguration();
        var root=_options.ManagementJournalRoot!;
        var spool=Environment.GetEnvironmentVariable("APFSACCESS_SPOOL_ROOT")??throw new IOException("Original production spool root is not configured.");
        var recovery=Environment.GetEnvironmentVariable("APFSACCESS_RECOVERY_ROOT")??throw new IOException("Stable recovery root is not configured.");
        var registrations=_ordinaryImageRegistrations.Where(r=>string.Equals(r.DestinationImage,request.ImagePath,StringComparison.OrdinalIgnoreCase)).ToArray();
        if(registrations.Length!=1)throw new IOException("ManagementRenameFreshRegistrationRequired");
        var record=NativeOrdinaryImageOwnership.Read(root,request.ImagePath,"0");
        using var retained=new NativeOrdinaryImageOwnership.RetainedLaunch(record,"0");
        retained.RequireRegistration(registrations[0],root,spool,recovery);
        if(record.LaunchBindings.Count!=0)
            return RenameRetainedRegisteredImage_NoLock(request,record,retained,spool,recovery,token);
        // This first-operation profile cannot infer authority for any past WAL or marker.
        if(Directory.EnumerateFileSystemEntries(spool).Any()||Directory.EnumerateFileSystemEntries(recovery).Any())
            throw new IOException("ManagementRenamePriorRuntimeEvidenceUnsupported");
        var priorIntent=NativeApfsVolumeRename.JournalDirFor(root,request.ImagePath);
        if(Directory.Exists(priorIntent)||File.Exists(priorIntent))
            throw new IOException("ManagementRenamePriorIntentUnsupported");
        using var original=new FileStream(record.CopiedFrom!,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(Convert.ToHexStringLower(SHA256.HashData(original))!=record.OriginalDigest)
            throw new IOException("ManagementRenameOriginalSourceChanged");
        using(var current=new FileStream(request.ImagePath,FileMode.Open,FileAccess.Read,FileShare.Read))
            if(Convert.ToHexStringLower(SHA256.HashData(current))!=record.OriginalDigest)
                throw new IOException("ManagementRenameFreshPreimageRequired");
        NativeManagementJournalAdmission.RequireImage(root,request.ImagePath,"0");
        var discovered=DiscoverUnownedDevice(request.ImagePath,true,token)??throw new IOException("ManagementRenameInventoryUnavailable");
        var inventory=new DeviceInventory(new(request.ImagePath,discovered.DisplayName,true),
            discovered.Volumes.Select(v=>CreateDiscoveredVolumeInfo(request.ImagePath,v)).ToArray(),discovered.Topology);
        if(!TopologyAdmission.Validate(inventory)||inventory.Volumes.Any(v=>v.RegisteredImage is not null||v.RegisteredFusion is not null||v.IsEncrypted||!CatalogMountPolicy.AllowsOrdinaryMount(v)))
            throw new IOException("ManagementRenameProfileUnsupported");
        var rows=inventory.Volumes.Where(v=>v.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture)==request.VolumeObjectId&&
            TopologyAdmission.SameUuid(v.CatalogContainerUuid,request.ContainerUuid)&&TopologyAdmission.SameUuid(v.CatalogVolumeUuid,request.VolumeUuid)).ToArray();
        if(rows.Length!=1)throw new IOException("ManagementRenameSelectedIdentityChanged");
        var scope=VerifyScopeDerivation.TryDerive(inventory,rows[0]).Scope??throw new IOException("ManagementRenameScopeUnproved");
        if(scope.StoreOffsetBytes!="0"||!VolumeTopologyProfile.IsBounded(scope)||
            scope.StoreSizeBytes!=new FileInfo(request.ImagePath).Length.ToString(CultureInfo.InvariantCulture))
            throw new IOException("ManagementRenameWholeOrdinaryImageRequired");
        if(scope.CheckpointXid!=request.PreimageXid)throw new IOException("ManagementRenamePreimageChanged");
        retained.RequireBinding();
        var kept=new NativeApfsVolumeRename(_observerRunner,NativeApfsVolumeRename.ResolvePackagedRenameTool(),root)
            .RenameVolumeAsync(request,token).GetAwaiter().GetResult();
        try{retained.RequireBinding();}
        catch(Exception error)when((error is IOException or UnauthorizedAccessException) &&
            kept.Code is not ManagementKeeperCodes.Refused and not ManagementKeeperCodes.InvalidRequest)
        {return new(false,0,ManagementKeeperCodes.Unproven,"Rename post-dispatch binding is unproven: "+error.Message);}
        return kept;
    }

    private ManagementKeeperRenameResult RenameRetainedRegisteredImage_NoLock(ManagementKeeperRenameRequest request,
        NativeOrdinaryImageOwnership.Record ownership, NativeOrdinaryImageOwnership.RetainedLaunch retained,
        string spool, string recovery, CancellationToken token)
    {
        var root=_options.ManagementJournalRoot!;
        foreach(var binding in ownership.LaunchBindings)
        {
            if(!File.Exists(binding.Wal)||!File.Exists(NativeRecoveryStorage.CanonicalNativeMarker(recovery,binding.RecoveryIdentity)))
                throw new IOException("ManagementRenameOriginalWalOrMarkerMissing");
        }
        using var original=new FileStream(ownership.CopiedFrom!,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(Convert.ToHexStringLower(SHA256.HashData(original))!=ownership.OriginalDigest)
            throw new IOException("ManagementRenameOriginalSourceChanged");
        NativeManagementJournalAdmission.RequireImage(root,request.ImagePath,"0");
        var discovered=DiscoverUnownedDevice(request.ImagePath,true,token)??throw new IOException("ManagementRenameInventoryUnavailable");
        var inventory=new DeviceInventory(new(request.ImagePath,discovered.DisplayName,true),
            discovered.Volumes.Select(v=>CreateDiscoveredVolumeInfo(request.ImagePath,v)).ToArray(),discovered.Topology);
        if(!TopologyAdmission.Validate(inventory)||inventory.Volumes.Any(v=>v.RegisteredFusion is not null))
            throw new IOException("ManagementRenameProfileUnsupported");
        var siblings=inventory.Volumes.Where(v=>v.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture)!=request.VolumeObjectId)
            .Select(v=>v.CatalogVolumeObjectId?.ToString(CultureInfo.InvariantCulture)??throw new IOException("ManagementRenameSiblingIdentityMissing")).ToArray();
        var censusRequest=new ManagementKeeperQuotaRequest(request.ImagePath,request.ContainerUuid,request.VolumeUuid,
            request.VolumeObjectId,request.PreimageXid,"0","0",siblings,root);
        _=RequireManagementQuotaOwnership(censusRequest,root,spool,recovery);
        VerifyScope scope;
        try{scope=BindManagementQuotaScope(censusRequest,inventory);}
        catch(IOException error)when(error.Message=="ManagementQuotaPreimageChanged")
        {throw new IOException("ManagementRenamePreimageChanged",error);}
        var observed=TopologyKeeper().Observe(scope,inventory,recovery,token);
        var wallets=BindManagementQuotaObservation(censusRequest,scope,observed);
        var bindings=NativeOrdinaryImageOwnership.RequireCensus(root,request.ImagePath,"0",spool,recovery,request.ContainerUuid,observed.Volumes);
        if(ownership.LaunchBindings.Count!=bindings.Count||ownership.LaunchBindings.Any(b=>!bindings.Contains(b)))
            throw new IOException("ManagementRenameHistoricalOwnershipUnsupported");
        var bound=new VolumeTopologyRequest("rename",request.ImagePath,root,"0",request.ContainerUuid,request.VolumeUuid,
            request.VolumeObjectId,request.PreimageXid,observed.SourceIdentity,spool,observed.Volumes);
        using var disposition=AcquireManagementQuotaDisposition(bound,bindings,recovery,root);
        retained.RequireBinding();
        var keeper=new NativeApfsVolumeRename(_observerRunner,NativeApfsVolumeRename.ResolvePackagedRenameTool(),root);
        var result=keeper.RenameWithOriginalWals(request,wallets,observed.SourceIdentity,token);
        try{retained.RequireBinding();}
        catch(Exception error)when((error is IOException or UnauthorizedAccessException) &&
            result.Code is not ManagementKeeperCodes.Refused and not ManagementKeeperCodes.InvalidRequest)
        {return new(false,0,ManagementKeeperCodes.Unproven,"Original rename post-dispatch binding is unproven: "+error.Message);}
        return result;
    }
}
