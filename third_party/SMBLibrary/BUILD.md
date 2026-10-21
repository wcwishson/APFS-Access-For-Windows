# SMBLibrary Source Extension

This dependency belongs to the optional StandardMount provider. Existing providers do not select it.

Upstream: [TalAloni/SMBLibrary](https://github.com/TalAloni/SMBLibrary), tag `v1.5.8`, exact commit `2edbcf3161084b51dbe11b8a960b0bc7c224b851`.
Download the [official source archive](https://codeload.github.com/TalAloni/SMBLibrary/zip/2edbcf3161084b51dbe11b8a960b0bc7c224b851) into a separate source directory. `source-pins.json` records the archive hash, every one of the 606 C# source hashes, patch hash and seven generated file hashes. Do not build inside or modify that source directory.

## Build

Set the MSBuild property `SMBLibrarySourceRoot` to the extracted directory containing `SMBLibrary` and `Utilities`. The new StandardMount project references `SMBLibrary.Pinned.csproj`. Its preparation step verifies the complete source inventory and applies `required-signing-and-clone.patch` into its intermediate directory, leaving upstream source intact. A missing, modified or additional source file refuses preparation.

```powershell
dotnet build src/ApfsAccess.StandardMount/ApfsAccess.StandardMount.csproj -p:SMBLibrarySourceRoot="D:/PrivateDependencies/SMBLibrary-2edbcf3161084b51dbe11b8a960b0bc7c224b851"
dotnet run --project tests/ApfsAccess.StandardMount.Tests -p:SMBLibrarySourceRoot="D:/PrivateDependencies/SMBLibrary-2edbcf3161084b51dbe11b8a960b0bc7c224b851"
```

No SMBLibrary NuGet package or ILRepack installation is required. The source project includes the pinned Utilities source in the SMBLibrary assembly, as the packaged upstream library does. `Net9Aliases.cs` selects the same upstream AES-CCM implementation when compiling against .NET 9. Upstream NTLM compile policy is retained. This does not claim new authentication mechanisms.

The normal build and publish scripts accept `-SMBLibrarySourceRoot` with the
same verified source directory. It can also be supplied through the
`SMBLibrarySourceRoot` environment variable. The scripts refuse a missing
source argument before native build or package-output cleanup:

```powershell
pwsh -File build/build.ps1 -Configuration Release -SMBLibrarySourceRoot "D:/PrivateDependencies/SMBLibrary-2edbcf3161084b51dbe11b8a960b0bc7c224b851"
pwsh -File build/publish.ps1 -SMBLibrarySourceRoot "D:/PrivateDependencies/SMBLibrary-2edbcf3161084b51dbe11b8a960b0bc7c224b851"
```

Normal packages containing `SMBLibrary.dll` include the verified upstream
source under `third_party/SMBLibrary/upstream`, the seven prepared changes
under `modified`, and the patch, extensions, license texts and this build
project alongside them. To rebuild that separate assembly from a package:

```powershell
dotnet build third_party/SMBLibrary/SMBLibrary.Pinned.csproj -p:SMBLibrarySourceRoot="<package>/third_party/SMBLibrary/upstream"
```

## Extension Contract

The new server constructor takes immutable `requireSigning`. StandardMount sets it true and disables SMB1. Negotiate advertises SigningRequired; authenticated session policy is server-required OR client-required. Guest/keyless sessions refuse under this profile. Before dispatch, every signed authenticated command is verified using the existing SMBLibrary crypto against the original padded wire bytes. Unsigned authenticated commands refuse when signing is required. The source extension does not add an SMB parser or cryptographic primitive.

Remote clone input remains the 40-byte SMB form. `TrustedCloneHelper` resolves both IDs inside the actual authenticated session and current tree, verifies the pinned non-durable ID representation, then calls `ISMB2CloneFileStore.CloneFileRange` with the actual store opens. No numeric ID-to-native-handle conversion, path lookup or ambient resolver is used. The native store must still enforce source/destination rights, identity, volume, range and durability. Providers without the typed interface refuse clone. NTFS can reject the actual clone operation even after correct routing; that is not clone support.

The lock patch corrects the upstream request length to its 24-byte prefix plus 24 bytes per element. Each element writes its flags and reserved field as 32-bit values. This keeps the serialized element within its actual 24-byte boundary and lets exact Windows lock packets pass the unchanged signed-wire bounds check. Access checks, lock ownership and conflict decisions remain with the native store.

Leases, reconnect, durable handles, async lock waiting and replay are not delivered by this extension. Native APFS capability flags remain authoritative for optional controls.

## License

Upstream and the patch/extensions are LGPL-3.0-or-later. Original copyright notices remain in patched files. `LICENSE.txt` is upstream's license text; `GPL-3.0.txt` supplies its referenced GNU GPL text. Preserve the exact upstream source, these changes and applicable license notices with any distribution; this private integration does not publish a package or change the default provider.
