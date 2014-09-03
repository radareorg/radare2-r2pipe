using System;
using System.IO;
using System.Net;
using System.Text;

public class MainClass {
	public static int Main(string[] args) {
		string uri = "http://cloud.rada.re/cmd/";
		string cmd = "pd 10";
		WebRequest request = WebRequest.Create(uri+cmd);
		WebResponse response = request.GetResponse();
		Stream dataStream = response.GetResponseStream ();
		StreamReader reader = new StreamReader (dataStream);
		string responseFromServer = reader.ReadToEnd ();
		Console.WriteLine (responseFromServer);
		response.Close ();
		return 0;
	}
}
