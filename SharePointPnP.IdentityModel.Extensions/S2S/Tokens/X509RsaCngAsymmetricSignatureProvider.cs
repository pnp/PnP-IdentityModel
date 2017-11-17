#if NET46
using System;
using System.Security.Cryptography;

namespace SharePointPnP.IdentityModel.Extensions.S2S.Tokens
{
    internal class X509RsaCngAsymmetricSignatureProvider : SignatureProvider
    {
        private bool _disposed;

        private RSACng _rsa;

        private HashAlgorithmName? _hashAlgorithm;

        public X509RsaCngAsymmetricSignatureProvider(System.IdentityModel.Tokens.X509AsymmetricSecurityKey x509Key)
        {
            Utility.VerifyNonNullArgument("x509Key", x509Key);
            var rsaCng = x509Key.GetAsymmetricAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", true) as RSACng;
            if (rsaCng == null)
            {
                throw new System.InvalidOperationException("Could not get algorithm from X509AsymmetricSecurityKey for \"RSACng\"");
            }
            this.Initialize(rsaCng);
        }

        public X509RsaCngAsymmetricSignatureProvider(RSACng rsa)
        {
            this.Initialize(rsa);
        }

        protected override void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                if (disposing)
                {
                    if (this._hashAlgorithm != null)
                    {
                        this._hashAlgorithm = null;
                    }
                    if (this._rsa != null)
                    {
                        this._rsa.Dispose();
                        this._rsa = null;
                    }
                }
                this._disposed = true;
            }
        }

        private void Initialize(RSACng rsa)
        {
            if (Utility.RequiresFipsCompliance)
            {
                CryptoConfig.AddOID("2.16.840.1.101.3.4.2.1", new string[]
                {
                    "SHA256CSP"
                });
                CryptoConfig.AddAlgorithm(typeof(SHA256CryptoServiceProvider), new string[]
                {
                    "SHA256CSP"
                });
                this._hashAlgorithm = new HashAlgorithmName("SHA256CSP");
            }
            else
            {
                this._hashAlgorithm = new HashAlgorithmName("SHA256");
            }
            this._rsa = rsa;
        }

        public override byte[] Sign(byte[] signingInput)
        {
            Utility.VerifyNonNullArgument("signingInput", signingInput);
            if (!this._hashAlgorithm.HasValue)
            {
                throw new NullReferenceException("Hash algorithm has not been set");
            }
            var signaturePadding = RSASignaturePadding.Pkcs1;
            return this._rsa.SignData(signingInput, this._hashAlgorithm.Value, signaturePadding);
        }

        public override bool Verify(byte[] signingInput, byte[] signature)
        {
            Utility.VerifyNonNullArgument("signingInput", signingInput);
            Utility.VerifyNonNullArgument("signature", signature);
            if (!this._hashAlgorithm.HasValue)
            {
                throw new NullReferenceException("Hash algorithm has not been set");
            }
            return this._rsa.VerifyData(signingInput, signature, this._hashAlgorithm.Value, RSASignaturePadding.Pkcs1);
        }
    }
}
#endif