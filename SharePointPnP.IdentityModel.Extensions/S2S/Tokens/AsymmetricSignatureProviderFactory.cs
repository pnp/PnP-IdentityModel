using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace SharePointPnP.IdentityModel.Extensions.S2S.Tokens
{
    /// <summary>
    /// Factory that builds the necessary <see cref="SignatureProvider"/> based on the Cryptographic Service Provider we are getting from the 
    /// framework. Until .NET 4.6 the default Crypt Service Provider is <see cref="RSACryptoServiceProviderProxy"/>. Starting with .NET 4.7, we are getting RSACng.
    /// </summary>
    internal class AsymmetricSignatureProviderFactory
    {
        /// <summary>
        /// Creates a signature provider for an asymetirc encryption scheme. The 
        /// </summary>
        /// <param name="asymmetricSecurityKey">The <see cref="X509AsymmetricSecurityKey"/> asymmetric security key.</param>
        /// <returns>A <see cref="SignatureProvider"/> that uses the crypto service provider assicated with the <paramref name="asymmetricSecurityKey"/></returns>
        /// <remarks>
        /// Until .NET 4.6 the default Crypt Service Provider is <see cref="RSACryptoServiceProviderProxy"/>. Starting with .NET 4.7, we are getting RSACng.
        /// </remarks>
        public static SignatureProvider CreateSignatureProvider(X509AsymmetricSecurityKey asymmetricSecurityKey)
        {
            Utility.VerifyNonNullArgument("asymmetricSecurityKey", asymmetricSecurityKey);
#if NET46
            var asymmetricAlgorithm = asymmetricSecurityKey.GetAsymmetricAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", true);
            if (asymmetricAlgorithm is RSACryptoServiceProvider)
            {
                return new X509AsymmetricSignatureProvider(asymmetricSecurityKey);
            }
            if (asymmetricAlgorithm is RSACng)
            {
                return new X509RsaCngAsymmetricSignatureProvider(asymmetricSecurityKey);
            }

            throw new System.InvalidOperationException(string.Format("Could not get asymetric signature provider of type \"{0}\"", asymmetricAlgorithm.GetType().Name));
#else
            //Older versions of the .NET Framework only know the RSACryptoServiceProvider. In this case, we can use the default implementation
            return new X509AsymmetricSignatureProvider(asymmetricSecurityKey);
#endif
        }
    }
}