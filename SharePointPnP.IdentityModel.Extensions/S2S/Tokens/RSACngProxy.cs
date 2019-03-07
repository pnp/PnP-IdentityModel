using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SharePointPnP.IdentityModel.Extensions.S2S.Tokens
{
    internal sealed class RSACngProxy : System.IDisposable
    {
        private bool _disposed;

        private bool _disposeRsa;

        private System.Security.Cryptography.RSACng _rsa;

        public RSACngProxy(System.Security.Cryptography.RSACng rsa)
        {
            Utility.VerifyNonNullArgument("rsa", rsa);

            this._rsa = rsa;
        }

        private void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                if (disposing && this._disposeRsa && this._rsa != null)
                {
                    this._rsa.Dispose();
                    this._rsa = null;
                }
                this._disposed = true;
            }
        }

        public byte[] SignData(byte[] signingInput, HashAlgorithmName hashAlgorithm)
        {
            var signaturePadding = RSASignaturePadding.Pkcs1;
            return this._rsa.SignData(signingInput, hashAlgorithm, signaturePadding);

        }

        public bool VerifyData(byte[] signingInput, HashAlgorithmName hashAlgorithm, byte[] signature)
        {
            return this._rsa.VerifyData(signingInput, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);

        }

        public void Dispose()
        {
            this.Dispose(true);
            System.GC.SuppressFinalize(this);
        }
    }
}
