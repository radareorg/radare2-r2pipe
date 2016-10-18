using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

#if HAVE_PIPES

using System.IO.Pipes;
#if __MonoCS__
using Mono.Unix;
#endif

namespace r2pipe
{
    public class RlangPipe : IR2Pipe
    {
#if __MonoCS__
        public UnixStream ureadStream;
        public UnixStream uwriteStream;
#endif
        public NamedPipeClientStream inclient;
        public StreamReader reader;
        public StreamWriter writer;

        /// <summary>
        /// Initializes a new instance of the <see cref="RlangPipe"/> class.
        /// </summary>
        public RlangPipe()
        {
#if __MonoCS__
            if (Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX) {

            ureadStream = new UnixStream(int.Parse(Environment.GetEnvironmentVariable("R2PIPE_IN")));
            reader = new StreamReader(ureadStream);
           
            uwriteStream = new UnixStream(int.Parse(Environment.GetEnvironmentVariable("R2PIPE_OUT")));
            writer = new StreamWriter(uwriteStream);

            } else {
#endif
            // Using named pipes on windows. I like this.
            inclient = new NamedPipeClientStream("R2PIPE_PATH");
            reader = new StreamReader(inclient);
            writer = new StreamWriter(inclient);
#if __MonoCS__
            }
#endif
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
            writer.WriteLine(command);
            writer.Flush();
            
            while (true)
            {
                char buffer = (char)reader.Read();
                if (buffer == 0x00) {
                    break;
                }
                sb.Append(buffer);
            }
            return sb.ToString().Trim();
        }

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
            await writer.WriteLineAsync(command);
            await writer.FlushAsync();
            while (true)
            {
                char[] buffer = new char[1024];

                int length = await reader.ReadAsync(buffer, 0, 1024);

                for (int i = 0; i < length; i++)
                {
                    if (buffer[i] == 0x00)
                        goto outer;

                    builder.Append(buffer[i]);
                }
            }
        outer:
            return builder.ToString().Trim();
        }

        public void Dispose()
        {
            reader.Dispose();
            writer.Dispose();
#if __MonoCS__
            if(Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX) {
                ureadStream.Dispose();
                uwriteStream.Dispose();
            }
            else {
#endif
            inclient.Dispose();
#if __MonoCS__
            }
#endif
        }
    }
}

#else // HAVE_PIPES

namespace r2pipe
{
    public class RlangPipe : IR2Pipe
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RlangPipe"/> class.
        /// </summary>
        public RlangPipe()
        {
            throw new ArgumentException("RLangPipe: Unsupported r2pipe backend");
        }

        public string RunCommand(string command)
        {
             return null;
        }

        public async Task<string> RunCommandAsync(string command)
        {
             return null;
        }

        public void Dispose()
        {
             /* do nothing */
        }
     }
}

#endif
