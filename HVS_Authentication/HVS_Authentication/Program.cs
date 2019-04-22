using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using HVS_Authentication.Src;

namespace HVS_Authentication
{
    class Program
    {
        private static Thread thr;

        static void Main(string[] args)
        {
            IniFileParser iniParser = new IniFileParser("config.ini");
            string user = iniParser.Read("username");
            string pass = iniParser.Read("password");
            Console.WriteLine(user + " - " + pass);
           
            HttpService.LoginAsync(user, pass, JWTService.GetComputerSid().Value, (response) =>{

                Debug.WriteLine(response);

                var token = response.Split(':').Last();                

                Console.WriteLine("Login Successful");
                

                var generatedToken = JWTService.GenerateToken(token, JWTService.GetComputerSid().Value);
                Console.WriteLine(generatedToken);

                Console.WriteLine("jwt token created");
                Constants.AccessToken = generatedToken;

                RunMethodInSeparateThread(StartServer);

                Console.WriteLine("Press Ctrl + C to Exit");               

            }).Wait();            

        }


        private static void RunMethodInSeparateThread(Action action)
        {
            thr = new Thread(new ThreadStart(action));            
            thr.Start();            
        }

        static void StartServer()
        {
            try
            {
                SocketServer.StartServer();
            }
            catch (ThreadAbortException ex)
            {
                Console.WriteLine("Thread is aborted and the code is "
                                                 + ex.ExceptionState);
            }

        }
    }

    
}
