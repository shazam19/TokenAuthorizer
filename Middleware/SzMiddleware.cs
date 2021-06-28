using TokenAuthorizer.CustomAttribute;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using TokenAuthorizer.Exceptions;
using System.Net;
using Microsoft.Extensions.Configuration;

namespace TokenAuthorizer.Middleware
{
    public class SzMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;

        public SzMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                var endpoint = context.Features.Get<IEndpointFeature>()?.Endpoint;
                var attribute = endpoint?.Metadata.GetMetadata<SzAttribute>();

                if (attribute == null)
                {
                    await _next(context);
                    return;
                }

                var accessToken = context?.Request.Headers["Authorization"];

                var token = string.Empty;

                if (accessToken.HasValue)
                {
                    token = accessToken.Value;
                }

                if (string.IsNullOrEmpty(token))
                {
                    throw new InvalidTokenException();
                }

                if (token.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
                {
                    token = token.Replace("bearer", "", StringComparison.OrdinalIgnoreCase);
                    token = token.Trim();
                }

                //var token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJCRTBEMjI0NS0wNTQ2LTRCMDktOEM1My1DRTE2MjQ3N0FDMzMiLCJzdWIiOiJlMzFiMzQ3Yy0xYjBlLTRmZWItYTY2OC1lNGU5M2FjM2QyMDIiLCJzaXRlX2lkIjoiRDUxRjVFQTAtMzhENC00RjlELUEzODItMkJCRTA3NjE4Qzc2Iiwib3JpZ2luIjoic2hvcHBlcm9uLnNlbGlzZWxvY2FsLmNvbSIsInNlc3Npb25faWQiOiJlY2FwLWQzNGMwN2RmLWRjZGMtNDQ2OS04MjgzLThhNzFlOTYyYmRlYiIsInVzZXJfaWQiOiJlMzFiMzQ3Yy0xYjBlLTRmZWItYTY2OC1lNGU5M2FjM2QyMDIiLCJkaXNwbGF5X25hbWUiOiJCYXNpYyBUZXN0Iiwic2l0ZV9uYW1lIjoiQXJjIFRlYW0iLCJ1c2VyX25hbWUiOiJiYXNpY0B5b3BtYWlsLmNvbSIsImVtYWlsIjoiYmFzaWNAeW9wbWFpbC5jb20iLCJwaG9uZV9udW1iZXIiOiIrODgwMTcyMjE3Njk0NCIsImxhbmd1YWdlIjoiZW4tVVMiLCJ1c2VyX2xvZ2dlZGluIjoiVHJ1ZSIsIm5hbWUiOiJlMzFiMzQ3Yy0xYjBlLTRmZWItYTY2OC1lNGU5M2FjM2QyMDIiLCJ1c2VyX2F1dG9fZXhwaXJlIjoiRmFsc2UiLCJ1c2VyX2V4cGlyZV9vbiI6IjAxLzAxLzAwMDEgMDA6MDA6MDAiLCJuYmYiOjE2MjM2NjYzODMsImV4cCI6MTYyMzY2NjgwMywiaXNzIjoiQ049RW50ZXJwcmlzZSBDbG91ZCBBcHBsaWNhdGlvbiBQbGF0Zm9ybSIsImF1ZCI6IioifQ.kLq1YfRIf-Qki8fzDtW4SnyaffUMx9Qb2vdaETevHS8_YWrqeErV1tcWSM6Zhki2pQhmoEdBVnb_wQxB6D_FdsbHcYymGzZxoBQuZNO0X61V7ff0IulBF2qG_Jg2f6m-SmMFvyXbcNtSwCXwInSJjseEXwDco1Jr_Ag49w1lMWyMVrFlqVRyRMSMp1CNfGiEF472GTaEuKgJGLVfcaO_Il8lVeXg-iMZuaFipN9vAMuRrLacZ9vz3lwm12pxH91oAaF4qoX7cUQ-AYGHI_yharDmIfhuvyjVCbNTG9AeiGjhjJBl5hMjefdWsPYsggre0-seaA2WsWivg-_ty0Qs8w";
                //var token = "FyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiJCRTBEMjI0NS0wNTQ2LTRCMDktOEM1My1DRTE2MjQ3N0FDMzMiLCJzdWIiOiJlMzFiMzQ3Yy0xYjBlLTRmZWItYTY2OC1lNGU5M2FjM2QyMDIiLCJzaXRlX2lkIjoiRDUxRjVFQTAtMzhENC00RjlELUEzODItMkJCRTA3NjE4Qzc2Iiwib3JpZ2luIjoic2hvcHBlcm9uLnNlbGlzZWxvY2FsLmNvbSIsInNlc3Npb25faWQiOiJlY2FwLWQzNGMwN2RmLWRjZGMtNDQ2OS04MjgzLThhNzFlOTYyYmRlYiIsInVzZXJfaWQiOiJlMzFiMzQ3Yy0xYjBlLTRmZWItYTY2OC1lNGU5M2FjM2QyMDIiLCJkaXNwbGF5X25hbWUiOiJCYXNpYyBUZXN0Iiwic2l0ZV9uYW1lIjoiQXJjIFRlYW0iLCJ1c2VyX25hbWUiOiJiYXNpY0B5b3BtYWlsLmNvbSIsImVtYWlsIjoiYmFzaWNAeW9wbWFpbC5jb20iLCJwaG9uZV9udW1iZXIiOiIrODgwMTcyMjE3Njk0NCIsImxhbmd1YWdlIjoiZW4tVVMiLCJ1c2VyX2xvZ2dlZGluIjoiVHJ1ZSIsIm5hbWUiOiJlMzFiMzQ3Yy0xYjBlLTRmZWItYTY2OC1lNGU5M2FjM2QyMDIiLCJ1c2VyX2F1dG9fZXhwaXJlIjoiRmFsc2UiLCJ1c2VyX2V4cGlyZV9vbiI6IjAxLzAxLzAwMDEgMDA6MDA6MDAiLCJuYmYiOjE2MjM2NjYzODMsImV4cCI6MTYyMzY2NjgwMywiaXNzIjoiQ049RW50ZXJwcmlzZSBDbG91ZCBBcHBsaWNhdGlvbiBQbGF0Zm9ybSIsImF1ZCI6IioifQ.kLq1YfRIf-Qki8fzDtW4SnyaffUMx9Qb2vdaETevHS8_YWrqeErV1tcWSM6Zhki2pQhmoEdBVnb_wQxB6D_FdsbHcYymGzZxoBQuZNO0X61V7ff0IulBF2qG_Jg2f6m-SmMFvyXbcNtSwCXwInSJjseEXwDco1Jr_Ag49w1lMWyMVrFlqVRyRMSMp1CNfGiEF472GTaEuKgJGLVfcaO_Il8lVeXg-iMZuaFipN9vAMuRrLacZ9vz3lwm12pxH91oAaF4qoX7cUQ-AYGHI_yharDmIfhuvyjVCbNTG9AeiGjhjJBl5hMjefdWsPYsggre0-seaA2WsWivg-_ty0Qs8w";

                var tokenParts = token.Split('.');

                if (tokenParts.Length != 3)
                {
                    throw new InvalidTokenException();
                }

                var ev = attribute.PositionalString;
                // add telemetry or logging here

                var certificatePath = _configuration["CertificatePath"];
                var certificatePassword = _configuration["CertificatePassword"];

                // "C:\Certificate\Public.pfx"
                //try
                {
                    var cert = new X509Certificate2("C:\\Certificate\\Public.pfx", "Selise@5033", X509KeyStorageFlags.MachineKeySet);

                    //var publicKey = Convert.ToBase64String(cert.GetPublicKey());
                    var publicKey = cert.GetPublicKey();

                    //var d = new RS256()
                    //var isValid = IsValid(tokenParts, publicKey);

                    //var rsa = CreateRsaProviderFromPublicKey(publicKey);

                    //var token64 = Convert.FromBase64String(token);

                    //var result = Decrypt(token64, publicKey);

                    var result = IsValid(tokenParts, publicKey);

                    if (!result)
                    {
                        //throw new UnauthorizedAccessException("Unauthorized token/source");

                        throw new InvalidTokenException();
                    }
                }
                //catch(Exception ex)
                //{
                //    Console.WriteLine("Error");
                //}


                //Console.WriteLine(ev);
                await _next(context);
            }
            catch (InvalidTokenException)
            {
                context.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
                context.Response.Headers.Clear();
                //context.Request.Headers.Clear();
                await context.Response.WriteAsync("Invalid token");
            }
        }

        private bool IsValid(string[] tokenParts, byte[] publicKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //rsa.ImportParameters(
            //  new RSAParameters()
            //  {
            //      Modulus = publicKey,
            //      //Exponent = FromBase64Url("AQAB")
            //  });

            rsa.ImportRSAPublicKey(publicKey, out int bytesRead);

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);

            rsaDeformatter.SetHashAlgorithm("SHA256");

            if (rsaDeformatter.VerifySignature(hash, FromBase64Url(tokenParts[2])))
                return true;

            return false;
        }

        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                                  .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }



        private byte[] Decrypt(byte[] input, byte[] publicKey)
        {
            byte[] decrypted;

            using(var rsa = new RSACryptoServiceProvider())
            {
                rsa.PersistKeyInCsp = false;
                //rsa.ImportParameters(rSAParameters);
                rsa.ImportSubjectPublicKeyInfo(publicKey, out int value);

                decrypted = rsa.Decrypt(input, true);

            }

            return decrypted;
        }

        private static RSA CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];

            var x509Key = Convert.FromBase64String(publicKeyString);

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            using (MemoryStream mem = new MemoryStream(x509Key))
            {
                using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    seq = binr.ReadBytes(15);       //read the Sequence OID
                    if (!CompareBytearrays(seq, seqOid))    //make sure Sequence for OID is correct
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8203)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    bt = binr.ReadByte();
                    if (bt != 0x00)     //expect null byte next
                        return null;

                    twobytes = binr.ReadUInt16();
                    if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                        binr.ReadByte();    //advance 1 byte
                    else if (twobytes == 0x8230)
                        binr.ReadInt16();   //advance 2 bytes
                    else
                        return null;

                    twobytes = binr.ReadUInt16();
                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    if (twobytes == 0x8102) //data read as little endian order (actual data order for Integer is 02 81)
                        lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
                    else if (twobytes == 0x8202)
                    {
                        highbyte = binr.ReadByte(); //advance 2 bytes
                        lowbyte = binr.ReadByte();
                    }
                    else
                        return null;
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {   //if first byte (highest order) of modulus is zero, don't include it
                        binr.ReadByte();    //skip this null byte
                        modsize -= 1;   //reduce modulus buffer size by 1
                    }

                    byte[] modulus = binr.ReadBytes(modsize);   //read the modulus bytes

                    if (binr.ReadByte() != 0x02)            //expect an Integer for the exponent data
                        return null;
                    int expbytes = (int)binr.ReadByte();        // should only need one byte for actual exponent data (for all useful values)
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                    var rsa = System.Security.Cryptography.RSA.Create();
                    RSAParameters rsaKeyInfo = new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    };
                    rsa.ImportParameters(rsaKeyInfo);

                    return rsa;
                }

            }
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }
}
