module R2pipe (R2Context(), open, cmd, cmdj) where
import Data.Aeson
import Data.Word
import System.IO
import System.Process
import qualified Data.ByteString.Lazy as L

withPipes p = p { std_in = CreatePipe, std_out = CreatePipe, std_err = CreatePipe }

createProcess' args = fmap f $ createProcess (withPipes args) where
    f (Just i, Just o, Just e, h) = (i, o, e, h)
    f _ = error "Failed to open pipes to the subprocess."

lHTakeWhile :: (Word8 -> Bool) -> Handle -> IO L.ByteString
lHTakeWhile p h = do
    c <- fmap L.head $ L.hGet h 1
    if p c
        then fmap (c `L.cons`) $ lHTakeWhile p h
        else return L.empty

-- This ADT is intended to have branches for {HTTP, TCP, ...} in the future
data R2Context = LocalCtx (Handle, Handle, Handle, ProcessHandle)

open :: String -> IO R2Context
open url = do
    handles@(_, hOut, _, _) <- createProcess' $ proc "r2" ["-q0", url]
    lHTakeWhile (/= 0) hOut -- drop the inital null that r2 emits
    return $ LocalCtx handles

cmd :: R2Context -> String -> IO L.ByteString
cmd (LocalCtx (hIn, hOut, _, _)) cmd = do
    hPutStrLn hIn cmd
    hFlush hIn
    lHTakeWhile (/= 0) hOut

cmdj :: R2Context -> String -> IO (Maybe Value)
cmdj = (fmap decode .) . cmd
