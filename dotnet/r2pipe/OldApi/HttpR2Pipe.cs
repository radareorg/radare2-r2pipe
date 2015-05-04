using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace r2pipe.OldApi
{
    [Obsolete("Please use the newer HttpR2Pipe Class.")]
    public class R2PipeHttp : HttpR2Pipe
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpR2Pipe"/> class.
        /// </summary>
        /// <param name="uri">The URI.</param>
        /// <exception cref="System.ArgumentException">URI must be HTTP(S)</exception>
        public R2PipeHttp(string uri) : base(new Uri(uri + "/"))
        { }

        [Obsolete("Please use QueuedR2Pipe, which supports Callbacks or the async method which does not need one.")]
        public void Cmd(string cmd, Action<string> cb)
        {
            cb(this.RunCommand(cmd));
        }

        [Obsolete("Please use the interface Member Command() instead.")]
        public string CmdSync(string cmd)
        {
            return this.RunCommand(cmd);
        }
    }
}
