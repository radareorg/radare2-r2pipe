class RCore
  @r2 : Void*
  def initialize # (@r2 : Void*)
    @r2 = RCoreC.new
  end
  def cmd(c : String) : String
    cres = RCoreC.cmd(@r2, c.to_unsafe)
    res = String.new(cres)
    RCoreC.libc_free(cres)
    return res
  end
  def finalize
    RCoreC.free(@r2)
  end
end

@[Link("r_core")]
lib RCoreC
  fun new = r_core_new() : Void*
  fun cmd = r_core_cmd_str(core: Void*, cmd: LibC::Char*) : LibC::Char*
  fun free = r_core_free(core: Void*)
  fun libc_free = free(core: Void*)
end

r2 = RCore.new
res = r2.cmd("?E Hello World")
print(res)



