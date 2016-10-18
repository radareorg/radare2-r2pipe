using System;
using r2pipe;

namespace ConsoleApplication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
	    var a = new DllR2Pipe();
	    Console.WriteLine("-> {0}", a.RunCommand("?V"));
            a.Dispose();
        }
    }
}
