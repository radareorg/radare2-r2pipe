
say R2CMD('?E hello from rexx')
exit

r2cmd: PROCEDURE EXPOSE globals.
  arg cmd
  fin = '/dev/fd/'getenv(R2PIPE_IN)
  fou = '/dev/fd/'getenv(R2PIPE_OUT)
  o = charout(fou, cmd''D2C(0))
  len = 0
  do while len == 0
    len = chars(fin)
  end
  return charin(fin,,len)

