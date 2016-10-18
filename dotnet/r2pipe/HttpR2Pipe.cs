using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace r2pipe
{
    public class HttpR2Pipe : IR2Pipe
    {

        /// <summary>
        /// The URI
        /// </summary>
        internal Uri uri;

        protected HttpClient client = new HttpClient();


        /// <summary>
        /// Initializes a new instance of the <see cref="HttpR2Pipe"/> class.
        /// </summary>
        /// <param name="uri">The URI (with trailing slash).</param>
        /// <exception cref="System.ArgumentException">URI must be HTTP(S)</exception>
        public HttpR2Pipe(string uri) :this (new Uri(uri))
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpR2Pipe"/> class.
        /// </summary>
        /// <param name="uri">The URI (with trailing slash).</param>
        /// <exception cref="System.ArgumentException">URI must be HTTP(S)</exception>
        public HttpR2Pipe(Uri uri)
        {
            if(!uri.Scheme.StartsWith("http"))
            {
                throw new ArgumentException("URI must be HTTP(S)");
            }

            this.uri = uri;
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
            return client.GetStringAsync(new Uri(uri, command)).Result;
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
            return await client.GetStringAsync(new Uri(uri, "/" + command));
        }
#endif

        public void Dispose()
        {
            client.Dispose();
        }
    }
}
