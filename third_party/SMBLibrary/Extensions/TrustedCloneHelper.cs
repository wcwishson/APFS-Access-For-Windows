// APFS Access extension to SMBLibrary, LGPL-3.0-or-later.
using System;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal static class TrustedCloneHelper
    {
        internal static NTStatus Clone(IOCtlRequest request, SMB2Session session, ISMBShare share,
            OpenFileObject destination)
        {
            if (request.Input == null || request.Input.Length != 40) return NTStatus.STATUS_INVALID_PARAMETER;
            if (!(share.FileStore is ISMB2CloneFileStore store)) return NTStatus.STATUS_NOT_SUPPORTED;
            var sourceId = new FileID(request.Input, 0);
            // This pinned server generates equal persistent/volatile IDs and
            // has no durable/reconnect handle namespace.
            if (sourceId.Persistent != sourceId.Volatile || request.FileId.Persistent != request.FileId.Volatile)
                return NTStatus.STATUS_FILE_CLOSED;
            var source = session.GetOpenFileObject(sourceId);
            if (source == null || destination == null || source.TreeID != request.Header.TreeID ||
                destination.TreeID != request.Header.TreeID || !Object.ReferenceEquals(session.GetConnectedTree(request.Header.TreeID), share))
                return NTStatus.STATUS_FILE_CLOSED;
            long sourceOffset = LittleEndianConverter.ToInt64(request.Input, 16);
            long destinationOffset = LittleEndianConverter.ToInt64(request.Input, 24);
            long length = LittleEndianConverter.ToInt64(request.Input, 32);
            if (sourceOffset < 0 || destinationOffset < 0 || length < 0 ||
                sourceOffset > Int64.MaxValue - length || destinationOffset > Int64.MaxValue - length)
                return NTStatus.STATUS_INVALID_PARAMETER;
            return store.CloneFileRange(source.Handle, destination.Handle, sourceOffset, destinationOffset, length);
        }
    }
}
