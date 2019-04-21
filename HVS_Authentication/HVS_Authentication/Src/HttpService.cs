using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Runtime.Serialization;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HVS_Authentication.Src
{
    [DataContract]
    internal class LoginParms
    {
        public LoginParms(string name,string pass,string id)
        {
            username = name;
            password = pass;
            uid = id;
        }

        [DataMember]
        internal string username;

        [DataMember]
        internal string password;

        [DataMember]
        internal string uid;    
    }

    class HttpService
    {
        static readonly string baseUrl = "http://68.183.181.245/";       

        public static async Task LoginAsync(string userName,string Pass, string sid,Action<string> completion)
        {
            
            using (HttpClient client = new HttpClient())
            {
                var myParams = new LoginParms(userName, Pass, sid);
                MemoryStream memStream = new MemoryStream();

                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(LoginParms));
                serializer.WriteObject(memStream, myParams);

                byte[] json = memStream.ToArray();
                memStream.Close();
                string jsonStr =  Encoding.UTF8.GetString(json, 0, json.Length);
                System.Diagnostics.Debug.WriteLine(jsonStr);

                var content = new StringContent(jsonStr, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(baseUrl + "auth/authenticate", content);
                var responseStr = await response.Content.ReadAsStringAsync();
                completion(responseStr);
            }
            

        }                
    }

}
