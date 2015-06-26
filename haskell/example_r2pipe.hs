import R2pipe
import qualified Data.ByteString.Lazy as L

showMainFunction ctx = do
    cmd ctx "s main"
    L.putStr =<< cmd ctx "pD `fl $$`"

main = do
    -- Run r2 locally
    open "/bin/ls" >>= showMainFunction
    -- Connect to r2 via HTTP (e.g. if "r2 -qc=h /bin/ls" is running)
    open "http://127.0.0.1:9090" >>= showMainFunction
