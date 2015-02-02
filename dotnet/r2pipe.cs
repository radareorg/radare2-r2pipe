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

    #region Delegates

    public delegate void CmdCallback(string res);

    #endregion Delegates

    public class CmdQueue
    {
        #region Fields

        public CmdCallback Callback;
        public string Command;

        #endregion Fields

        #region Constructors

        public CmdQueue(string cmd, CmdCallback cb)
        {
            this.Command = cmd;
            this.Callback = cb;
        }

        #endregion Constructors

        #region Methods

        public override string ToString()
        {
            return Command;
        }

        #endregion Methods
    }

    public class R2Pipe
    {
        #region Fields

        /*
        // Use this method for the synchronous api.. or just use a thread
           private static string ReadToChar(StreamReader sr, char splitCharacter) {
           char nextChar;
           StringBuilder line = new StringBuilder();
           while (sr.Peek() > 0) {
           nextChar = (char)sr.Read();
           if (nextChar == splitCharacter) return line.ToString();
           line.Append(nextChar);
           }
           return line.Length == 0 ? null : line.ToString();
           }
         */
        private bool doAsync;
        StringBuilder outputBuilder;
        Process p;
        ProcessStartInfo psi;
        List<CmdQueue> queue;

        #endregion Fields

        #region Constructors

        public R2Pipe(string file = null, bool doAsync = true)
        {
            this.doAsync = doAsync;
            this.queue = new List<CmdQueue> ();
            this.outputBuilder = new StringBuilder();
            if (file == null)
                file = "-";
            psi = new ProcessStartInfo ();
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardInput = true;
            psi.UseShellExecute = false;
            psi.Arguments = "-q0 "+file;
            //psi.FileName = "/usr/bin/r2";
            psi.FileName = "radare2";

            p = new Process();
            p.StartInfo = psi;
            if (doAsync) {
                p.EnableRaisingEvents = true;
                queue.Add (new CmdQueue ("init", (x) => {
                        Console.WriteLine ("Initialization is done");
                    }));
                p.OutputDataReceived += new DataReceivedEventHandler (
                        delegate (object sender, DataReceivedEventArgs e) {
                            int token = e.Data.IndexOf ('\0');
                            if (token != -1) {
                                if (token >0) {
                                    string rest = e.Data.Substring (0, token);
                                    outputBuilder.Append (rest+"\n");
                                }

                                CmdQueue cq = queue[0];
                                if (cq.Callback != null) {
                                    cq.Callback (""+outputBuilder);
                                }
                                queue.RemoveAt (0);

                                outputBuilder = new StringBuilder();
                                outputBuilder.Append (e.Data.Substring (token)+"\n");
                            } else {
                                //Console.WriteLine ("No token yet. go on");
                                outputBuilder.Append (e.Data+"\n");
                            }
                        });
                // there's no way to read byte per byte asyncronously?
                p.Start ();
                p.BeginOutputReadLine();
            } else {
                p.Start ();
                // ignore first run
                p.StandardOutput.Read();
            }
        }

        #endregion Constructors

        #region Methods

        public string Cmd(string c, CmdCallback cb = null)
        {
            if (this.doAsync) {
                StreamWriter sw = p.StandardInput;
                queue.Add (new CmdQueue (c, cb));
                // ;?e is a hackaround to bypass the imposibility to read byte-per-byte
                sw.WriteLine (c+";?e");
                return null;
            }
            string str = CmdSync (c);
            cb (str);
            return str;
        }

        public string CmdSync(string cmd=null)
        {
            var sb = new StringBuilder ();
            p.StandardInput.WriteLine (cmd);
            while (true) {
                var b = p.StandardOutput.Read();
                if (b == 0) break;
                sb.Append ((char)b);
            }
            return sb.ToString ();
        }

        public void Quit()
        {
            this.Cmd ("q!");
            p.WaitForExit();
        }

        public void QuitSync()
        {
            this.CmdSync ("q!");
            p.WaitForExit();
        }

        #endregion Methods
    }

    public class R2PipeHttp
    {
        #region Fields

        string uri;

        #endregion Fields

        #region Constructors

        public R2PipeHttp(string uri)
        {
            //this.queue = new List<CmdQueue> ();
            if (!uri.StartsWith ("http://")) {
                if (uri.IndexOf ("://") != -1) {
                    // invalid uri
                    this.uri = null;
                    return;
                } else {
                    uri = "http://"+uri;
                }
            }
            if (!uri.EndsWith ("/")) {
                uri += "/";
            }
            this.uri = uri;
        }

        #endregion Constructors

        #region Methods

        /*
           public static ManualResetEvent allDone = new ManualResetEvent(false);
        List<CmdQueue> queue;
        const int BUFFER_SIZE = 1024;
        private static void ReadCallBack(IAsyncResult asyncResult) {
            // Get the RequestState object from AsyncResult.
            RequestState rs = (RequestState)asyncResult.AsyncState;

            // Retrieve the ResponseStream that was set in RespCallback.
            Stream responseStream = rs.ResponseStream;

            // Read rs.BufferRead to verify that it contains data.
            int read = responseStream.EndRead( asyncResult );
            if (read > 0) {
                // Prepare a Char array buffer for converting to Unicode.
                Char[] charBuffer = new Char[BUFFER_SIZE];

                // Convert byte stream to Char array and then to String.
                // len contains the number of characters converted to Unicode.
                int len =
                    rs.StreamDecode.GetChars(rs.BufferRead, 0, read, charBuffer, 0);

                String s = new String(charBuffer, 0, len);
                System.Console.WriteLine("_____ "+s);

                // Append the recently read data to the RequestData stringbuilder
                // object contained in RequestState.
                rs.RequestData.Append(
                        Encoding.ASCII.GetString(rs.BufferRead, 0, read));

                // Continue reading data until
                // responseStream.EndRead returns –1.
                IAsyncResult ar = responseStream.BeginRead(
                        rs.BufferRead, 0, BUFFER_SIZE,
                        new AsyncCallback(ReadCallBack), rs);
            } else {
                if(rs.RequestData.Length>0)
                {
                    //  Display data to the console.
                    string strContent;
                    strContent = rs.RequestData.ToString();
                }
                // Close down the response stream.
                responseStream.Close();
                // Set the ManualResetEvent so the main thread can exit.
                //allDone.Set();
            }
            return;
        }
        private static void RespCallback(IAsyncResult ar) {
            // Get the RequestState object from the async result.
            RequestState rs = (RequestState) ar.AsyncState;
            // Get the WebRequest from RequestState.
            WebRequest req = rs.Request;
            // Call EndGetResponse, which produces the WebResponse object
            //  that came from the request issued above.
            WebResponse resp = req.EndGetResponse(ar);

            //  Start reading data from the response stream.
            Stream ResponseStream = resp.GetResponseStream();

            // Store the response stream in RequestState to read
            // the stream asynchronously.
            rs.ResponseStream = ResponseStream;

            //  Pass rs.BufferRead to BeginRead. Read data into rs.BufferRead
            IAsyncResult iarRead = ResponseStream.BeginRead(rs.BufferRead, 0,
                    BUFFER_SIZE, new AsyncCallback(ReadCallBack), rs);
        }
        public async Task<string> CmdAsync(string cmd, CmdCallback cb = null) {
        #if 0
               if (System.Net.Http)
               var client = new System.Net.Http.HttpClient();
               Task<string> getstringTask = client.GetStringAsync (uri+cmd);
               queue.Add (new CmdQueue (cmd, cb));
               string data = await getstringTask;
               cb (data);
               return getstringTask;
        #endif
            WebRequest request = WebRequest.Create(uri+cmd);
            RequestState rs = new RequestState ();
            queue.Add (new CmdQueue (cmd, cb));
            rs.Request = request;
            IAsyncResult r = (IAsyncResult) request.BeginGetResponse(
                    new AsyncCallback (RespCallback), rs);
        }

        public void WaitAll() {
            Task.WaitAll (tasks.ToArray ());
        }
        */
        public void Cmd(string cmd, CmdCallback cb = null)
        {
            WebRequest request = WebRequest.Create(uri+cmd);
            WebResponse response = request.GetResponse();
            Stream dataStream = response.GetResponseStream ();
            StreamReader reader = new StreamReader (dataStream);
            string responseFromServer = reader.ReadToEnd ();
            response.Close ();
            cb (responseFromServer);
        }

        public string CmdSync(string cmd)
        {
            WebRequest request = WebRequest.Create(uri+cmd);
            WebResponse response = request.GetResponse();
            Stream dataStream = response.GetResponseStream ();
            StreamReader reader = new StreamReader (dataStream);
            string responseFromServer = reader.ReadToEnd ();
            response.Close ();
            return responseFromServer;
        }

        #endregion Methods

        #region Nested Types

        // The RequestState class passes data across async calls.
        private class RequestState
        {
            #region Fields

            public byte[] BufferRead;
            public WebRequest Request;
            public StringBuilder RequestData;
            public Stream ResponseStream;

            // Create Decoder for appropriate enconding type.
            public Decoder StreamDecode = Encoding.UTF8.GetDecoder();

            const int BufferSize = 1024;

            #endregion Fields

            #region Constructors

            public RequestState()
            {
                BufferRead = new byte[BufferSize];
                RequestData = new StringBuilder(String.Empty);
                Request = null;
                ResponseStream = null;
            }

            #endregion Constructors
        }

        #endregion Nested Types
    }
}