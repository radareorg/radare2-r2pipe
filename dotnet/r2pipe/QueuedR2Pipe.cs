using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace r2pipe
{
    public class QueuedR2Pipe : Queue<R2Command>, IDisposable
    {
        private IR2Pipe pipe;

        private bool iOpenedPipe = false;

#if !PORTABLE
        /// <summary>
        /// Initializes a new instance of the <see cref="QueuedR2Pipe"/> class.
        /// </summary>
        /// <param name="file">The file to examine.</param>
        /// <param name="executable">Path to the radare2 executable.</param>
        public QueuedR2Pipe(string file, string executable) : this(new R2Pipe(file, executable))
        {
            iOpenedPipe = true;
        }
#endif

        /// <summary>
        /// Initializes a new instance of the <see cref="QueuedR2Pipe"/> class, using a HttpR2Pipe.
        /// </summary>
        /// <param name="uri">The URI for the HttpR2Pipe.</param>
        public QueuedR2Pipe(Uri uri) : this(new HttpR2Pipe(uri)) 
        {
            iOpenedPipe = true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="QueuedR2Pipe"/> class.
        /// </summary>
        /// <param name="pipe">The r2pipe to use.</param>
        public QueuedR2Pipe(IR2Pipe pipe)
        {
            this.pipe = pipe;
        }

#if !PORTABLE
        /// <summary>
        /// Initializes a new instance of the <see cref="QueuedR2Pipe"/> class.
        /// </summary>
        /// <param name="file">The file to examine.</param>
        public QueuedR2Pipe(string file) : this(new R2Pipe(file)) 
        {
            iOpenedPipe = true;
        }
#endif

        /// <summary>
        /// Executes the commands.
        /// </summary>
        public void ExecuteCommands()
        {
            while (this.Count > 0)
            {
                R2Command cmd = this.Dequeue();

                string result = pipe.RunCommand(cmd.Command);
                cmd.Callback(result);
            }
        }

#if !OLDNETFX
        /// <summary>
        /// Executes the commands asynchronous.
        /// </summary>
        public async void ExecuteCommandsAsync()
        {
            while(this.Count > 0)
            {
                R2Command cmd = this.Dequeue();

                string result = await pipe.RunCommandAsync(cmd.Command);
                cmd.Callback(result);
            }
        }
#endif

        public void Dispose()
        {
            if (iOpenedPipe)
                pipe.Dispose();
        }
    }
}
