using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace r2pipe
{
    public interface IR2Pipe : IDisposable
    {

        /// <summary>
        /// Executes given RunCommand in radare2
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <returns>Returns a string </returns>
        string RunCommand(string command);

#if !OLDNETFX
        /// <summary>
        /// Commands the asynchronous.
        /// </summary>
        /// <param name="command">The command.</param>
        /// <returns></returns>
        Task<string> RunCommandAsync(string command);
#endif
    }
}
