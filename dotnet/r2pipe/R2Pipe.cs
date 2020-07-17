namespace r2pipe
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    //using r2pipe.OldApi;

    public class R2Pipe : IR2Pipe, IDisposable
    {
        /// <summary>
        /// Gets the radare2 path.
        /// </summary>
        /// <value>
        /// The radare2 path.
        /// </value>
        public string Radare2Path { get; private set; }

        [Obsolete("Please use RunCommandAsync() or the QueuedR2Pipe class")]
        public bool doAsync { get; set; }

        /// <summary>
        /// The r2 process
        /// </summary>
        internal Process r2Process;

        /// <summary>
        /// Initializes a new instance of the <see cref="R2Pipe"/> class.
        /// </summary>
        /// <param name="file">The file.</param>
        public R2Pipe()
		: this("-", "radare2") {
	}

        /// <summary>
        /// Initializes a new instance of the <see cref="R2Pipe"/> class.
        /// </summary>
        /// <param name="file">The file.</param>
        public R2Pipe(string file)
            : this(file, "radare2")
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="R2Pipe"/> class.
        /// </summary>
        /// <param name="file">The file.</param>
        /// <param name="r2executable">The r2executable.</param>
        public R2Pipe(string file, string r2executable)
        {
            if (file == null)
                file = "-";

            r2Process = new Process();
            r2Process.StartInfo = new ProcessStartInfo()
            {
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                Arguments = "-q0 " + file,
                FileName = r2executable
            };

            r2Process.Start();
            r2Process.StandardInput.AutoFlush = true;
            r2Process.StandardInput.NewLine = "\n";
            // ignore first run
            r2Process.StandardOutput.Read();
            // Console.WriteLine(r2Process.StandardOutput.Read());
        }

        /// <summary>
        /// Disposes this object. Exits r2 (if not already done) and disposes the process object too.
        /// </summary>
        public void Dispose()
        {
            if (!r2Process.HasExited)
            {
                this.RunCommand("q!");
                r2Process.WaitForExit();
            }
            r2Process.Dispose();
        }

        /// <summary>
        /// Executes given RunCommand in radare2
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <returns>
        /// Returns a string
        /// </returns>
        public string RunCommand(string command)
        {
            var sb = new StringBuilder();
            r2Process.StandardInput.WriteLine(command);
            r2Process.StandardInput.Flush();
            
            while (true)
            {
                char buffer = (char)r2Process.StandardOutput.Read();

                if (buffer == 0x00)
                    break;

                sb.Append(buffer);
            }
            return sb.ToString();
        }

#if !OLDNETFX
        /// <summary>
        /// Executes given RunCommand in radare2 asynchronously
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <returns>
        /// Returns a string
        /// </returns>
        public async Task<string> RunCommandAsync(string command)
        {
            StringBuilder builder = new StringBuilder();
            await r2Process.StandardInput.WriteLineAsync(command);
            await r2Process.StandardInput.FlushAsync();
            while (true)
            {
                char[] buffer = new char[1024];

                int length = await r2Process.StandardOutput.ReadAsync(buffer, 0, 1024);

                for (int i = 0; i < length; i++)
                {
                    if (buffer[i] == 0x00)
                        goto outer;

                    builder.Append(buffer[i]);
                }
            }
        outer:
            return builder.ToString();
        }
#endif
    }



}
