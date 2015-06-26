module R2pipe (R2Context(), open, cmd, cmdj) where
import Data.Char
import Data.Word
import Network.HTTP
import System.IO
import System.Process
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Lazy as L

withPipes p = p { std_in = CreatePipe, std_out = CreatePipe, std_err = CreatePipe }

createProcess' args = fmap f $ createProcess (withPipes args) where
    f (Just i, Just o, Just e, h) = (i, o, e, h)
    f _ = error "createProcess': Failed to open pipes to the subprocess."

stringToLBS = L.pack . map (fromIntegral . ord)

lHTakeWhile :: (Word8 -> Bool) -> Handle -> IO L.ByteString
lHTakeWhile p h = do
    c <- fmap L.head $ L.hGet h 1
    if p c
        then fmap (c `L.cons`) $ lHTakeWhile p h
        else return L.empty

data R2Context = HttpCtx String
               | LocalCtx (Handle, Handle, Handle, ProcessHandle)

open :: String -> IO R2Context
open url@('h':'t':'t':'p':_) = return $ HttpCtx (url ++ "/cmd/")
open filename = do
    handles@(_, hOut, _, _) <- createProcess' $ proc "r2" ["-q0", filename]
    lHTakeWhile (/= 0) hOut -- drop the inital null that r2 emits
    return $ LocalCtx handles

cmd :: R2Context -> String -> IO L.ByteString
cmd (HttpCtx url) cmd = fmap stringToLBS $ getResponseBody =<< simpleHTTP (getRequest (url ++ cmd))
cmd (LocalCtx (hIn, hOut, _, _)) cmd = hPutStrLn hIn cmd >> hFlush hIn >> lHTakeWhile (/= 0) hOut

cmdj :: R2Context -> String -> IO (Maybe JSON.Value)
cmdj = (fmap JSON.decode .) . cmd
