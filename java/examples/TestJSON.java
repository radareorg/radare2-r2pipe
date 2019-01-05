import org.radare.r2pipe.R2Pipe;
import java.util.Map;
import java.util.HashMap;
import javax.json.*;
import javax.json.stream.*;
import java.io.StringWriter;

public class TestJSON {
	public static String jsonStringify(JsonObject obj) {
		Map<String, Boolean> config = new HashMap<>();
		config.put(JsonGenerator.PRETTY_PRINTING, true);
		JsonWriterFactory jwf = Json.createWriterFactory(config);
		StringWriter sw = new StringWriter();
		try (JsonWriter jsonWriter = jwf.createWriter(sw)) {
			jsonWriter.writeObject(obj);
		}
		return sw.toString();
	}

	public static void main (String[] args) {
		try {
			R2Pipe r2p = new R2Pipe ("/bin/ls");
			//R2Pipe r2p = new R2Pipe ("http://cloud.rada.re/cmd/", true);
			System.out.println (r2p.cmd ("pd 10"));
			System.out.println ("==============");
			System.out.println (r2p.cmd ("px 32"));
			JsonObject obj = r2p.cmdj ("ij");
			String intrp = obj.getJsonObject("bin").getString("intrp");
			String pretty = jsonStringify(obj);
			System.out.println (pretty);
			System.out.println (intrp);
			r2p.quit();
		} catch (Exception e) {
			System.err.println (e);
		}
	}
}
