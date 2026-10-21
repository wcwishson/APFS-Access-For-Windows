// APFS Access extension to SMBLibrary, LGPL-3.0-or-later.
using System;
using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.SMB2;

namespace SMBLibrary.Server
{
    public partial class SMBServer
    {
        public bool RequireSigning { get; private set; }
        public bool ListenerClosed => m_listenerSocket == null || m_listenerSocket.SafeHandle.IsClosed;
        protected System.Runtime.InteropServices.SafeHandle RetainListenerHandle() => m_listenerSocket == null ? null : m_listenerSocket.SafeHandle;

        public SMBServer(SMBShareCollection shares, GSSProvider securityProvider, bool requireSigning)
            : this(shares, securityProvider)
        { RequireSigning = requireSigning; }

        private bool ValidateRequestSignature(SMB2Command request, byte[] wireBytes, int offset,
            int length, ulong sessionId, ConnectionState state)
        {
            if (offset < 0 || length < SMB2Header.Length || offset > wireBytes.Length - length ||
                (request.Header.NextCommand != 0 && length % 8 != 0) || request.Length > length)
                return false;
            var connected = state as SMB2ConnectionState;
            var session = connected == null ? null : connected.GetSession(sessionId);
            if (request is NegotiateRequest || (request is SessionSetupRequest && session == null))
                return !request.Header.IsSigned;
            if (session == null)
                return !request.Header.IsSigned && (!RequireSigning || sessionId == 0 && request is EchoRequest);
            if (!request.Header.IsSigned) return !RequireSigning && !session.SigningRequired;
            if (session.SigningKey == null || session.SigningKey.Length == 0) return false;
            // The existing crypto clears the signature field. Verify a copy of
            // the exact original padded command before related-ID rewriting.
            var original = new byte[length];
            Buffer.BlockCopy(wireBytes, offset, original, 0, length);
            return SMB2Cryptography.VerifySignature(original, ToSMB2Dialect(state.Dialect), session.SigningKey);
        }
    }
}
