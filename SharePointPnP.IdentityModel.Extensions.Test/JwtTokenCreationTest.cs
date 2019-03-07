using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharePointPnP.IdentityModel.Extensions.S2S.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using X509SigningCredentials = Microsoft.IdentityModel.SecurityTokenService.X509SigningCredentials;

namespace SharePointPnP.IdentityModel.Extensions.Test
{
    [TestClass]
    public class JwtTokenCreationTest
    {
        [TestMethod]
        public void CreateTokenTest()
        {
            var certFile = @".\Certificate\Test.pfx";
            var password = "Password1+";

            var certificate = new X509Certificate2(certFile, password);
            var signingCredentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

            var actorClaims = new List<JsonWebTokenClaim>();
            actorClaims.Add(new JsonWebTokenClaim(JsonWebTokenConstants.ReservedClaims.NameIdentifier, "TestName"));
            var actorToken = new JsonWebSecurityToken(
                issuer: "Test Issuer",
                audience: "TestAudience",
                validFrom: new DateTime(2017, 1, 1),
                validTo: new DateTime(2017, 12, 31, 23, 59, 59),
                signingCredentials: signingCredentials,
                claims: actorClaims);

            var actorTokenString = new JsonWebSecurityTokenHandler().WriteTokenAsString(actorToken);

            Assert.IsNotNull(actorTokenString);
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjhMcjBkRjJGRC00QXlUbXhzNnh4enRqYUl6WSJ9.eyJhdWQiOiJUZXN0QXVkaWVuY2UiLCJpc3MiOiJUZXN0IElzc3VlciIsIm5iZiI6IjE0ODMyMjUyMDAiLCJleHAiOiIxNTE0NzYxMTk5IiwibmFtZWlkIjoiVGVzdE5hbWUifQ.Z_8DKOQiXldAMyJj2BGNzfJd2cTm_XqEcgsAOFyeKwHGJ9yx4uYUM9V7FAUFRPzW7fsb1I2LIS8RDo_riw9m5c8xeequ1noAYbydOZIDHuM9tefplCsve0_cIzek6lV0B0jykDj7OFtJMsDs9TQEtKcjVDGkBK4BnHUwUTLB_lYdzTjMm7WXOpFxz5c74tP5vaER1nuFhtftO5Hsy7jKyRRgdhKJ2o3Do_-LGdEfG9m51dUSb5E8odVGu1vGBQVsc88a11y5uFzORL7cm6hu2RwEELIzfd7bdHruQ9BB5mpS4AGzD4QxtHs2jgYXQ4-HqWFvnpJ-Z89_xWcmo-wOKA", actorTokenString);
        }

        [TestMethod]
        public void CreateTwoTokensTest()
        {
            var certFile = @".\Certificate\Test.pfx";
            var password = "Password1+";

            var certificate = new X509Certificate2(certFile, password);
            var signingCredentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

            var actorClaims = new List<JsonWebTokenClaim>();
            actorClaims.Add(new JsonWebTokenClaim(JsonWebTokenConstants.ReservedClaims.NameIdentifier, "TestName"));
            var actorToken = new JsonWebSecurityToken(
                issuer: "Test Issuer",
                audience: "TestAudience",
                validFrom: new DateTime(2017, 1, 1),
                validTo: new DateTime(2017, 12, 31, 23, 59, 59),
                signingCredentials: signingCredentials,
                claims: actorClaims);

            var tokenHandler = new JsonWebSecurityTokenHandler();
            var firstActorTokenString = tokenHandler.WriteTokenAsString(actorToken);

            Assert.IsNotNull(firstActorTokenString);
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjhMcjBkRjJGRC00QXlUbXhzNnh4enRqYUl6WSJ9.eyJhdWQiOiJUZXN0QXVkaWVuY2UiLCJpc3MiOiJUZXN0IElzc3VlciIsIm5iZiI6IjE0ODMyMjUyMDAiLCJleHAiOiIxNTE0NzYxMTk5IiwibmFtZWlkIjoiVGVzdE5hbWUifQ.Z_8DKOQiXldAMyJj2BGNzfJd2cTm_XqEcgsAOFyeKwHGJ9yx4uYUM9V7FAUFRPzW7fsb1I2LIS8RDo_riw9m5c8xeequ1noAYbydOZIDHuM9tefplCsve0_cIzek6lV0B0jykDj7OFtJMsDs9TQEtKcjVDGkBK4BnHUwUTLB_lYdzTjMm7WXOpFxz5c74tP5vaER1nuFhtftO5Hsy7jKyRRgdhKJ2o3Do_-LGdEfG9m51dUSb5E8odVGu1vGBQVsc88a11y5uFzORL7cm6hu2RwEELIzfd7bdHruQ9BB5mpS4AGzD4QxtHs2jgYXQ4-HqWFvnpJ-Z89_xWcmo-wOKA", firstActorTokenString);

            var secondActorTokenString = tokenHandler.WriteTokenAsString(actorToken);

            Assert.IsNotNull(secondActorTokenString);
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjhMcjBkRjJGRC00QXlUbXhzNnh4enRqYUl6WSJ9.eyJhdWQiOiJUZXN0QXVkaWVuY2UiLCJpc3MiOiJUZXN0IElzc3VlciIsIm5iZiI6IjE0ODMyMjUyMDAiLCJleHAiOiIxNTE0NzYxMTk5IiwibmFtZWlkIjoiVGVzdE5hbWUifQ.Z_8DKOQiXldAMyJj2BGNzfJd2cTm_XqEcgsAOFyeKwHGJ9yx4uYUM9V7FAUFRPzW7fsb1I2LIS8RDo_riw9m5c8xeequ1noAYbydOZIDHuM9tefplCsve0_cIzek6lV0B0jykDj7OFtJMsDs9TQEtKcjVDGkBK4BnHUwUTLB_lYdzTjMm7WXOpFxz5c74tP5vaER1nuFhtftO5Hsy7jKyRRgdhKJ2o3Do_-LGdEfG9m51dUSb5E8odVGu1vGBQVsc88a11y5uFzORL7cm6hu2RwEELIzfd7bdHruQ9BB5mpS4AGzD4QxtHs2jgYXQ4-HqWFvnpJ-Z89_xWcmo-wOKA", secondActorTokenString);

        }
    }
}
