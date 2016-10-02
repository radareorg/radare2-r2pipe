import org.radare.r2pipe.*;

def r2 = new R2Pipe("/bin/ls");
println r2.cmd("?V")
println r2.cmd("pd 10")
r2.quit()
