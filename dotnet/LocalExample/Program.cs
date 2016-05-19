using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using r2pipe;

namespace LocalExample
{
    class Program
    {
        static void Main(string[] args)
        {

#if __MonoCS__
            using (IR2Pipe pipe = new R2Pipe("/bin/ls"))
#else
            using (IR2Pipe pipe = new R2Pipe(@"C:\Windows\notepad.exe", @"C:\radare2\radare2.exe"))
#endif
            {
                Console.WriteLine("Hello r2! " + pipe.RunCommand("?V"));

                Task<string> async = pipe.RunCommandAsync("?V");

                // To use non-blocking async stuff in console applications, you need an async context. Google helps you.

                // calling Result will block ulitmately.
                Console.WriteLine("Hello async r2!" + async.Result);

                // We can also issue multiple command sequentially, using a QueuedR2Pipe.
                // Note however that if we supply the pipe to use we must not call dispose on the pipe.

                QueuedR2Pipe qr2 = new QueuedR2Pipe(pipe);

                qr2.Enqueue(new R2Command("x", (string result) => { Console.WriteLine("Result of x:\n {0}", result); }));
                qr2.Enqueue(new R2Command("pi 10", (string result) => { Console.WriteLine("Result of pi 10:\n {0}", result); }));

                // note that this can also be done asynchronously via qr2.ExecuteCommandsAsync();
                qr2.ExecuteCommands();
            }
        }
    }
}
