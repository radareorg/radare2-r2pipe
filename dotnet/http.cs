using System;
using System.Threading;
using System.Threading.Tasks;

using r2pipe;

public class MainClass
{
    #region Methods

    public static int Main(string[] args)
    {
        var web = new R2PipeHttp("http://cloud.rada.re/cmd/");
        Console.WriteLine ("--> "+web.CmdSync ("p8 32"));

        web.Cmd("?V", (version) => {
            Console.WriteLine ("Version: {0}", version);
        });
        web.Cmd("pdf @ entry0", (code) => {
            Console.WriteLine ("Entrypoint:\n{0}", code);
        });
        /*
        string str = await web.CmdAsync("x");
        //Thread.Sleep (10000);
        //Task.WaitAll();
        */
        return 0;
    }

    #endregion Methods
}