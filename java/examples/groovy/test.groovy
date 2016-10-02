/* Groovy.r2pipe hello world -- 2016 - pancake@nopcode.org */

import org.radare.r2pipe.*;
import groovy.json.JsonSlurper;
import groovy.json.JsonOutput;

class R2 {
	def r2;
	def cmd = { x -> r2.cmd(x).trim() }
	def cmdj = { x -> new JsonSlurper().parseText(this.cmd(x)) }
	def quit = { r2.quit() }
}

def r2 = new R2(r2: new R2Pipe("/bin/ls"))
println r2.cmd("?V")
def obj = r2.cmdj("ij").bin
println JsonOutput.prettyPrint(JsonOutput.toJson(obj))
println ("Interpreter: " + obj.intrp);
r2.quit()
