using System;
using r2pipe;

namespace DllExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string osName = System.Environment.OSVersion.ToString().Split(' ')[0];

            const string fileName = "r2pipe.dll";

            using (IR2Pipe pipe = new DllR2Pipe())
            {
                Console.WriteLine("Hello r2! " + pipe.RunCommand("?V"));

                pipe.RunCommand("o " + fileName);
                Console.WriteLine("Hello r2! " + pipe.RunCommand("pd 20"));
                /* no async support yet */
            }
        }
    }
}
