# r2pipe.vim

This vim plugin allows you to run r2 commands into the current Vim buffer

## Installation

Just type `make`. If you want to get rid of that run: `make uninstall`

Note that the same code works with neovim. But it's not yet installed. Contribs are welcome

## How to use

In one terminal start the r2 webserver

In vim open

## Future

Right now this is just a PoC, but there are a lot of things to be done to improve the integration between r2 and vim

* [ ] Use r2p instead of `curl` (one less dependency, and support socket files, pipes..)
* [ ] Make interactive buffers and use the right syntax highlighting for disasm, hexa, ..
* [ ] Setup split layouts to navigate function list, disasm, etc
* [ ] Improve apis
