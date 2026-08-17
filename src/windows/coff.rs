/*
    We don't parse COFF at a top-level, so this program won't take object files
    as input. We do parse the COFF header inside Windows executables, since every
    PE carries one directly after the PE signature.

    The decision came down to a single factor: you aren't going to see an object
    file if you are looking at malware. If you do, the author made a mistake and
    this program misses that opportunity. The other time one shows up without it
    being a mistake is on a build server, which isn't the job this was written for.

    That makes object files rare enough as an input that they didn't fit the scope.
    Maybe I'll be wrong later and need to parse COFF top-level. An object file isn't
    a smaller version of this header, though. It keeps the symbol table and the
    relocations that the linker throws away, so it holds more than a finished PE.
*/
