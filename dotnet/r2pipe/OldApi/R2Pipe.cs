using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace r2pipe.OldApi
{
    public static class R2PipeOldExtensions
    {
        /// <summary>
        /// Quits this instance.
        /// </summary>
        /// <remarks>Obsolete.</remarks>
        [Obsolete("R2Pipe implements IDisposable, please use Dispose() instead or consider using a using block.")]
        public static void Quit(this R2Pipe pipe)
        {
            if (pipe.doAsync)
            {
                pipe.RunCommandAsync("q!").GetAwaiter().OnCompleted(() =>
                {
                    pipe.Dispose();
                    return;
                });
            }

            pipe.Dispose();
        }

        /// <summary>
        /// Quits the instance.
        /// </summary>
        /// <remarks>Obsolete.</remarks>
        [Obsolete("R2Pipe implements IDisposable, please use Dispose() instead or consider using a using block.")]
        public static void QuitSync(this R2Pipe pipe)
        {
            pipe.Dispose();
        }


        /// <summary>
        /// Executes a Command synchronized
        /// </summary>
        /// <param name="pipe">r2pipe</param>
        /// <param name="cmd">The command to execute.</param>
        /// <returns>result of the command</returns>
        [Obsolete("Please use the Interface Member RunCommand(string command) instead")]
        public static string CmdSync(this R2Pipe pipe, string cmd)
        {
            return pipe.RunCommand(cmd);
        }

        /// <summary>
        /// Commands the specified c.
        /// </summary>
        /// <param name="c">The c.</param>
        /// <param name="cb">The cb.</param>
        /// <returns></returns>
        [Obsolete("Please use the Interface Member RunCommand() or RunCommandAsync() instead")]
        public static async Task<string> Cmd(this R2Pipe pipe, string c, Action<string> cb)
        {
            if (pipe.doAsync)
            {
                string s = await pipe.RunCommandAsync(c);
                cb(s);          
                return null;
            }

            string str = pipe.CmdSync(c);
            cb(str);
            return str;
        }
    }
}
