// APFS Access extension to SMBLibrary, LGPL-3.0-or-later.
namespace SMBLibrary
{
    // Only the authenticated server dispatch supplies these actual store opens.
    // SMB FileIds never become OS handles or native owner capabilities.
    public interface ISMB2CloneFileStore
    {
        NTStatus CloneFileRange(object sourceHandle, object destinationHandle,
            long sourceOffset, long destinationOffset, long length);
    }
}
