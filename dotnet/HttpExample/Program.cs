using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using r2pipe;

namespace HttpExample
{
    class Program
    {
        static void Main(string[] args)
        {
            using(IR2Pipe pipe = new HttpR2Pipe("http://cloud.rada.re/cmd/"))
            {
                Console.WriteLine(pipe.RunCommand("p8 32"));

                // you can use the queue here too:
                QueuedR2Pipe qr2 = new QueuedR2Pipe(pipe);

                qr2.Enqueue(new R2Command("?V", (string result) => { 
                    Console.WriteLine("Version: {0}", result); 
                }));

                qr2.Enqueue(new R2Command("pdf @ entry0", (string result) =>
                {
                    Console.WriteLine("Entrypoint: \n{0}", result);
                }));

                qr2.ExecuteCommands();
            }
        }
    }
}
