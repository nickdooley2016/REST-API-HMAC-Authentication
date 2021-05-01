using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace API
{
    public class APIAuthentication
    {
        public static string GetHMACSha256(String data, String key)
        {
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.ASCII.GetBytes(key)))
            {
                return BitConverter.ToString(hmac.ComputeHash(Encoding.ASCII.GetBytes(data))).Replace("-", "").ToLower();
            }
        }


        private async Task<bool> IsAuthenticated(HttpRequest request, string PublicKey, string PrivateKey, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            string requestContentBase64String = string.Empty;
            string requestUri = request.GetDisplayUrl();
            string requestHttpMethod = request.HttpContext.Request.Method;

            string signatureRawData = String.Format("{0}{1}{2}{3}{4}", PublicKey, requestHttpMethod, requestUri, requestTimeStamp, nonce);

            string HMAC = GetHMACSha256(signatureRawData, PrivateKey);


            if (incomingBase64Signature.ToLower() == HMAC.ToLower())
            {
                return true;
            }
            else
            {
                return false;
            }
        }


        public async Task<bool> CheckIncomingAPIRequest(HttpRequest req) //Server side
        {

            string data = req.HttpContext.Request.Headers["Auth"];


            if (data.Split(':').Length != 4) return false;


            var PublicKey = data.Split(":")[0];

            if (System.Runtime.Caching.MemoryCache.Default.Contains(PublicKey)) return false;

            var incomingBase64Signature = data.Split(":")[1];
            var nonce = data.Split(":")[2];
            var requestTimeStamp = data.Split(":")[3];
            var PrivateKey = "";

            var rec = await _databaseContext.API.Where(x => x.PublicKey == PublicKey).FirstOrDefaultAsync();

            if (rec != null)
            {
                PrivateKey = rec.PrivateKey;
            }
            else
            {
                return false;
            }


            if (!await IsAuthenticated(req, PublicKey, PrivateKey, incomingBase64Signature, nonce, requestTimeStamp))
            {
                return false;
            }
            else
            {
                return true;
            }

        }

        public static string generateHMACSignature() //Client Side
        {
            string URL = "https://www.domain.com";
            string urlParameters = "/api/v1/testcall";
            string PublicKey = "PUBLICKEY";
            string PrivateKey = "PRIVATEKEY";
            string RequestMethod = "GET";

            Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            Int32 Nonce = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            var concatenatedString = PublicKey + RequestMethod + URL + urlParameters + unixTimestamp.ToString() + Nonce.ToString();

            var HMACsig = GetHMACSha256(concatenatedString, PrivateKey);

            return PublicKey + ":" + HMACsig + ":" + Nonce.ToString() + ":" + unixTimestamp.ToString();
        }

    }
}
