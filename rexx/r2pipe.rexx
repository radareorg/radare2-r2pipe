-- r2pipe hello world program in rexx
-- known to work on regina's rexx on macos
-- getenv is not portable, we can use '8'

Say r2cmd('?E hello from rexx')

Exit

r2cmd: PROCEDURE EXPOSE globals.
  arg cmd
  fin = '/dev/fd/'Getenv(R2PIPE_IN)
  fou = '/dev/fd/'Getenv(R2PIPE_OUT)
  o = CharOut(fou, cmd''D2C(0))
  len = 0
  DO while len == 0
    len = Chars(fin)
  END
  return CharIn(fin,,len)
