import R2Pipe
import qualified Data.ByteString.Lazy as L

showMainFunction ctx = do
    cmd ctx "s main"
    L.putStr =<< cmd ctx "pD `fl $$`"

main = do
    -- Run r2 locally
    open (Just "/bin/ls") >>= showMainFunction
    -- Pick up pipes from parent r2 process
    open Nothing >>= showMainFunction
    -- Connect to r2 via HTTP (e.g. if "r2 -qc=h /bin/ls" is running)
    open (Just "http://127.0.0.1:9090") >>= showMainFunction
