## EXI

> Disclaimer

Most of the information here is here on a temporary status. It will eventually be migrated to Wikipages here in the Github repository. Additionally, a lot of this information is not final. Learning takes places in phases. As I am still learning, I am also still trying to decide the type of narration for the Wikipages. 

If you have any questions, feel free to reach out in the mean time. You can find me here in my Discord server: [Discord]https://discord.gg/9ggw425YS3


> What is exi?

In short, it's a program that lets you read what is inside of an executable. Exi was created as part of a much bigger learning experience. Originally, I wanted to learn about malware. As I was going through the project (the program you are seeing now is not the first iteration, nor the second or third), I realized that in order to understand how malware works, I'd need to have a more in-depth view into computers. 

For someone wanting to learn how malware works, they'll need to know two essential stages: static and runtime. An important note is that runtime analysis isn't in the scope of this project. It's also important to note that you don't really call runtime analysis, runtime analysis. It is just debugging. Debugging a program is a skill itself and one that this project does not teach. 

This project primarily exists because it contains everything that I've ever learned regarding the subjects. However, it does have another purpose. It is a research project. This project asks a very important question: How effective is static analysis in the determination of an executable marked with malware? Now clearly, I will rephrase the wording of this question. But the question will remain the same. I chose this question because the answer is surprisingly multifaceted. 

When you read (not execute) a program with this program, your goal is typically to see if malware exists. Now, to be straight, you won't get a clear answer. Instead, you learn how to recognize patterns and flags that give you a probability of whether or not malware is present in the file you are reading. The phrase I'll commonly use is "indicitive but not definitive". Everything you'll learn could be indicitive that there is malware but it isn't definitive. Definitive just means that you've executed the suspicious file and you are finding out the hard way, especially if you don't have a configured environment to safely execute malware. For the purposes of this project, you won't see any data samples from malware for a while. Instead, we will look at data samples coming from legitimate programs, so you can learn what "normal" looks like and learn what an executable looks like underneath.

### Headers

1. DOS Header

Back in 1981, Microsoft released MS-DOS, or Microsoft Disk Operating System for IBM personal computers. MS-DOS was a 16-bit command-line operating system that wasn't exactly capable of much according to today's technological standards, but was cutting-edge at the time of release and heavily involved in the push to do more with computers. This header is 64-bytes in total and contains the following "fields":

- `e_magic` (0x00, 2 bytes) - the "MZ" signature, and the reason anything else in this list ever gets read at all.
- `e_cblp` (0x02, 2 bytes) - how many bytes are actually being used on the very last page of the file. DOS liked to think about files in 512-byte pages, so this was simply the leftover.
- `e_cp` (0x04, 2 bytes) - how many of those 512-byte pages the file takes up in total.
- `e_crlc` (0x06, 2 bytes) - the number of entries sitting in the DOS relocation table.
- `e_cparhdr` (0x08, 2 bytes) - the size of this header, though measured in 16-byte "paragraphs" rather than in bytes. Four paragraphs works out to 64 bytes, which is where the size of the header itself comes from.
- `e_minalloc` (0x0A, 2 bytes) - the smallest amount of extra memory, again in paragraphs, that the program needs on top of its own image before DOS should even bother starting it.
- `e_maxalloc` (0x0C, 2 bytes) - the most extra memory the program would happily take. In practice this was nearly always set to 0xFFFF, which was really just the program asking for everything the machine had.
- `e_ss` (0x0E, 2 bytes) - the initial stack segment, relative to wherever DOS happened to drop the program in memory.
- `e_sp` (0x10, 2 bytes) - the initial stack pointer.
- `e_csum` (0x12, 2 bytes) - a checksum of the file, which sounds useful right up until you learn that essentially nobody ever filled it in. It was being left at zero even back in 1985.
- `e_ip` (0x14, 2 bytes) - the initial instruction pointer, which is really just the DOS-era way of saying "the entry point".
- `e_cs` (0x16, 2 bytes) - the initial code segment, once again relative to the load address.
- `e_lfarlc` (0x18, 2 bytes) - the file offset of the DOS relocation table. This one is quietly more interesting than it looks, because a value of 0x40 or higher was the old convention for signalling that there is a newer, non-DOS header hiding somewhere in the file.
- `e_ovno` (0x1A, 2 bytes) - the overlay number. Programs too large to fit in memory used to get chopped into overlays that DOS would swap in and out as needed, and a value of 0 simply means "this is the main program, not one of the pieces".
- `e_res[4]` (0x1C, 8 bytes) - reserved, which in practice has always just meant unused.
- `e_oemid` (0x24, 2 bytes) - an identifier for the OEM, from a time when that mattered.
- `e_oeminfo` (0x26, 2 bytes) - additional OEM information, where the meaning depended entirely on whatever `e_oemid` had to say.
- `e_res2[10]` (0x28, 20 bytes) - reserved again, and the largest single stretch of unused space anywhere in the header.
- `e_lfanew` (0x3C, 4 bytes) - the file offset where the PE signature can be found.

Most of these are considered "historic" because they don't necessarily have any applicability in the programs that run today. However, two of these are actively used and do have an actual purpose: 0x00 (`e_magic`) and 0x3C (`e_lfanew`).

0x00, also referred to as `e_magic`, validates that the file begins with "MZ". "MZ" stands for Mark Zbikowski, who was one of the main designers of MS-DOS. Parse this field to validate a Windows or DOS executable. Byte order matters here. Sitting on disk, the two bytes are 0x4D 0x5A in that order. Read as a little-endian 16-bit integer, that very same pair becomes 0x5A4D. Neither one is wrong, they are simply two different ways of looking at the exact same two bytes.

0x3C, or `e_lfanew`, is the bridge to modern Windows. Microsoft did not want to maintain different file formats for different systems. Instead, they decided to utilize the DOS header as a wrapper. In modern 32-bit and 64-bit executables, `e_lfanew` holds an offset (dedicated) pointer that tells the operating system where the real Windows executable header (known as "PE\0\0") begins. This forces Windows to jump over the second DOS section, called the DOS Stub. That pointer is a file offset rather than a memory address, because at the moment the loader reads it there is nothing mapped anywhere yet. It is just a position in the bytes sitting on disk, and it is stored as a signed 32-bit value.

So out of all 64 bytes, the loader genuinely cares about two fields. The remaining 60 are read by nothing at all.

2. DOS Stub

The MS-DOS stub is rather interesting because it is a necessary "error" message. It is not "required" to be a generic message. It can be a fully functional 16-bit MS-DOS application inside of the executable, even on x86-64. In general, it most typically contains an embedded string that simply says that the program cannot be run in DOS mode. This section handles unsupported environments gracefully. Without it, users would experience crashes or unexpected and confusing system behavior with no reason why.

Back in the late 1980's and early 1990's, it was common for users to switch back and forth between MS-DOS and Windows. Someone attempting to run a Windows program while using DOS was extremely common, resulting in system crashes and other undefined, symptomatic behaviors. MS-DOS has no idea what 32-bit or 64-bit instructions are. It only ever understood 16-bit instructions because that is what it was designed to understand.

Because of the potential for undefined behavior, Microsoft's toolchain emits a small 16-bit MS-DOS program into every Windows application, which prints a message and exits if the file is ever launched from DOS. This is a linker convention rather than a rule the loader goes out of its way to enforce. Windows itself never looks at the stub, never executes it, and does not particularly care whether it is missing or has been swapped out for something else entirely. As for how much room the stub occupies, that is not really up to the stub. The region simply runs from the end of the DOS header to wherever `e_lfanew` happens to point, so the size is decided by that field instead.

3. Rich Header

Tucked in between the end of the DOS stub and the start of the PE signature is a block that Microsoft has never documented and, to this day, has never officially acknowledged. It shows up in more or less anything built with the Microsoft toolchain from roughly Visual Studio 6 onward. The loader does not read it, no specification mentions it, and yet it is sitting there in a very large portion of the Windows software on your machine right now.

Structurally it is a run of 8-byte pairs, and each pair records one tool that had a hand in building the binary along with how many objects that particular tool contributed. You get a product identifier, the exact build number of that product, and a count. The whole block is masked with a XOR key and closed off by the ASCII tag "Rich", with the key itself following along right behind it. The marker at the start, "DanS", only becomes readable once you have undone the mask.

What all of that adds up to is essentially a build receipt. The block quietly records which pieces of the toolchain were involved in producing the file and what exact patch level they were sitting at, which means two binaries compiled in the same environment end up carrying the same set of pairs, while binaries compiled somewhere else do not. Nothing in the loader ever consults it, and stripping it out has no effect whatsoever on whether the program runs.

4. Portable Executable Signature

As briefly noted previously, "PE\0\0" is found using the dedicated offset pointer found in the initial DOS header field called `e_lfanew`. This signature is rather specific, using these sets of bytes: 50 45 00 00.

When the program is executed, the Windows loader performs the previous steps in order. It reads the first two bytes of the program (0x5A4D) to verify the signature. The loader then immediately jumps to 0x3C (`e_lfanew`) to read the 4-byte integer, which contains the file offset where the PE signature begins. The kernel maps the first page of the file in so that it can read the headers, then checks that offset for exactly 0x00004550. If these bytes are malformed or missing, the operating system "bails" out and refuses to launch the program.

All of that describes the Windows loader specifically. A PE does not have to be handed to the operating system in order to be mapped. Code can read the section table and lay the image out in memory entirely on its own, and a loader written that way only performs whichever of these checks its author felt like writing. See "Reflective DLL Injection" for more information.

5. COFF File Header

COFF, or the Common Object File Format, is quite a bit older than Windows itself. It came out of AT&T's Unix System V in the early 1980's as a replacement for the older a.out format, and for years afterward it was the standard object format across commercial Unix. When Microsoft set out to build Windows NT, they picked up COFF for their object files and then built the Portable Executable format on top of it. That is why a Windows executable in 2026 still opens with a header that was designed for a version of Unix which stopped shipping a very long time ago. The PE specification itself arrived alongside Windows NT 3.1 in 1993.

This header gives basic information pertaining to the identity and structure of the metadata and the executable. It is 20 bytes and sits immediately after the PE signature:

- `Machine` (2 bytes) - the architecture this file was built for. 0x014C is 32-bit x86, 0x8664 is x86-64, and 0xAA64 is ARM64.
- `NumberOfSections` (2 bytes) - how many entries you should expect to find in the section table. The loader draws a hard line at 96 and will not accept any more than that.
- `TimeDateStamp` (4 bytes) - seconds counted from January 1st 1970, recording the moment the linker produced the file. Reproducible builds do something a little different here and swap in a hash of the file's contents instead of an actual time, since a real timestamp would make every build come out slightly different.
- `PointerToSymbolTable` (4 bytes) - the file offset of the COFF symbol table. This has been deprecated for images for a long while now and is normally just 0.
- `NumberOfSymbols` (4 bytes) - the entry count that goes along with the field above, and the same story applies.
- `SizeOfOptionalHeader` (2 bytes) - how many bytes the next header takes up. In an object file, as opposed to a finished executable, this is simply 0.
- `Characteristics` (2 bytes) - a set of flags describing the file as a whole. Whether it is an executable image, whether it is a DLL, whether it is a system file, whether the relocations have been stripped out, and whether it is comfortable with addresses above 2GB all live in here together.

6. Optional Header

The name here is a leftover from COFF and it is honestly a little misleading, because there is nothing optional about this header in an executable. It is completely mandatory. The reason it ended up with that name is that in a COFF *object file*, meaning the intermediate output the compiler hands over to the linker, it genuinely is absent. `SizeOfOptionalHeader` comes out as 0 and the section table follows immediately after. So the name is describing the format in general rather than the executable case specifically.

The very first field decides the shape of everything that comes after it. `Magic` is 0x010B for PE32 and 0x020B for PE32+, and that single value changes the width of the pointer-sized fields further down, which in turn changes the size of the entire header from 224 bytes to 240. Read this one wrong and every field you touch afterward is quietly shifted.

The standard fields, which are the ones inherited from COFF:

- `Magic` (2 bytes) - 0x010B or 0x020B, as above.
- `MajorLinkerVersion` / `MinorLinkerVersion` (1 byte each) - which version of the linker actually produced the file.
- `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData` (4 bytes each) - running totals across every section of each kind.
- `AddressOfEntryPoint` (4 bytes) - where execution begins, given as an RVA. A DLL is perfectly within its rights to leave this sitting at 0.
- `BaseOfCode` (4 bytes) - the RVA where the code section starts.
- `BaseOfData` (4 bytes) - the RVA where the data section starts, and this one is **PE32 only**. In PE32+ the field does not exist at all, because `ImageBase` grew to 8 bytes and simply took the space for itself.

The Windows-specific fields, which are the ones the loader really acts on:

- `ImageBase` (4 or 8 bytes) - the address in memory the image would prefer to be mapped at. By convention that is 0x400000 for a 32-bit executable, 0x10000000 for a DLL, and 0x140000000 for a 64-bit executable. Ever since ASLR came along this has been more of a polite request than any kind of guarantee.
- `SectionAlignment` (4 bytes) - how sections are aligned once they have been mapped into memory. Normally 4096, matching the page size, since the kernel hands out memory a page at a time and there is not much sense in doing it any other way.
- `FileAlignment` (4 bytes) - how sections are aligned while they are still sitting on disk. Normally 512, which matches a disk sector for much the same reason.
- `MajorOperatingSystemVersion` / `MinorOperatingSystemVersion` (2 bytes each) - the OS version this image expects to find.
- `MajorImageVersion` / `MinorImageVersion` (2 bytes each) - the version of this particular image, set by whoever developed it.
- `MajorSubsystemVersion` / `MinorSubsystemVersion` (2 bytes each) - the subsystem version this image expects.
- `Win32VersionValue` (4 bytes) - reserved, and required to be 0.
- `SizeOfImage` (4 bytes) - how many bytes the image takes up once it has been mapped, rounded up to `SectionAlignment`. This is the outer boundary that every RVA in the file has to fall inside of.
- `SizeOfHeaders` (4 bytes) - everything covered so far plus the section table, rounded up to `FileAlignment`. It marks where the headers finish and where the first section's raw data is allowed to begin.
- `CheckSum` (4 bytes) - a checksum that only really gets validated for drivers, kernel modules, and a handful of system DLLs. Most ordinary user-mode software just leaves it sitting at 0.
- `Subsystem` (2 bytes) - 1 for native, meaning drivers, 2 for the Windows GUI, and 3 for the console.
- `DllCharacteristics` (2 bytes) - the security posture of the binary, despite the name suggesting it only ever applies to DLLs. ASLR, DEP, Control Flow Guard, high-entropy 64-bit ASLR, and whether the image forces integrity checks are all packed in here.
- `SizeOfStackReserve` / `SizeOfStackCommit` / `SizeOfHeapReserve` / `SizeOfHeapCommit` (4 or 8 bytes each) - the initial memory reservations the image is asking for.
- `LoaderFlags` (4 bytes) - obsolete, and must be 0.
- `NumberOfRvaAndSizes` (4 bytes) - how many data directory entries come next. In practice this is always 16.

Those two alignment fields are the reason a file sitting on disk and that same file sitting in memory are not laid out the same way. A section starts at a multiple of 512 in the file and a multiple of 4096 in memory, so the distance between where a section lives on disk and where it lives once mapped keeps growing with every section that comes before it.

7. Data Directories

The tail end of the optional header is an array of 16 entries, and each entry is nothing more than a pair of 4-byte values: an RVA and a size. They are the format's index. Rather than making you go hunting through the file for the import table, the header simply tells you where it is.

- 0 - Export table
- 1 - Import table
- 2 - Resources
- 3 - Exception table, meaning unwind information, which is mandatory on x64
- 4 - Certificate table, which is where Authenticode signatures live
- 5 - Base relocation table
- 6 - Debug directory
- 7 - Architecture, reserved
- 8 - Global pointer
- 9 - Thread Local Storage directory
- 10 - Load configuration table
- 11 - Bound import table
- 12 - Import Address Table
- 13 - Delay import descriptor
- 14 - CLR runtime header, which shows up if and only if this is a .NET assembly
- 15 - Reserved, must be 0

Entry 4 is the one exception to the pattern, and it is an easy one to get caught out by. Every other directory in that list stores an RVA. The certificate table stores a raw file offset instead, and there is a good reason for it: the signature gets appended to the file and is never mapped into memory at all, so there is no section sitting there for an RVA to resolve against in the first place.

8. Section Table

Immediately after the optional header comes an array of 40-byte section headers, one for each section, in whatever count `NumberOfSections` gave us. This table is the map between the two layouts we have been talking about, and every translation between a file offset and an RVA has to pass through it.

- `Name` (8 bytes) - ASCII, padded out with NULs. A name that happens to fill all 8 bytes carries no terminator at all, so there is nothing to stop on when you read it.
- `VirtualSize` (4 bytes) - how large the section is once it has been mapped.
- `VirtualAddress` (4 bytes) - the RVA of the section once it has been mapped.
- `SizeOfRawData` (4 bytes) - how large the section is on disk, rounded up to `FileAlignment`.
- `PointerToRawData` (4 bytes) - the file offset where the section's bytes actually sit.
- `PointerToRelocations` / `NumberOfRelocations` - used in object files, and simply 0 in images.
- `PointerToLinenumbers` / `NumberOfLinenumbers` - deprecated debugging information, also 0.
- `Characteristics` (4 bytes) - readable, writable and executable, along with whether the section holds code, initialized data or uninitialized data, and whether the loader should throw it away once it is finished with it.

`VirtualSize` and `SizeOfRawData` are describing the same section in two different places, and they are rarely equal to each other. When virtual size is the larger of the two, the difference is space that the loader zero-fills at load time, and that space has no bytes in the file whatsoever. When raw size is the larger, the difference is padding that does exist in the file but that the loader never gets around to mapping.

### Sections

Just remember that the names are convention rather than rule. The loader routes everything off the `Characteristics` flags and never so much as glances at the name, so a section called `.text` that is not marked executable simply is not executable, and a section called absolutely anything at all that is marked executable will run perfectly happily. The names below are just what compilers have collectively agreed to use over the years.

- `.text` - the compiled machine code. The name comes from Unix, where a program's code segment has been called text since the 1970's, back when the code really was the readable part of the file. Marked read and execute.
- `.data` - initialized global and static variables that the program is allowed to modify. Marked read and write.
- `.rdata` - read-only initialized data. String literals, constants, the import and export tables in most modern builds, and C++ vtables all end up in here. Marked read only.
- `.bss` - uninitialized globals, which the loader zeroes out on your behalf. Its `SizeOfRawData` is 0 because there is genuinely nothing to store on disk, only a size to reserve. The name stands for "Block Started by Symbol" and was inherited from an assembler written for the IBM 704 back in the late 1950's, which makes it comfortably the oldest naming convention still riding along inside a modern Windows binary.
- `.idata` - the import table. Modern linkers usually fold this into `.rdata`, so more often than not you will not see it as a section of its own.
- `.edata` - the export table. Common enough in DLLs, and fairly rare in executables.
- `.rsrc` - resources. Icons, dialogs, menus, embedded manifests, version information, and whatever else the developer felt like embedding. It is stored as a tree rather than a flat list, and the contents of any given resource are just arbitrary bytes.
- `.reloc` - base relocations, which is a list of addresses that need fixing up if the image cannot be loaded at its preferred `ImageBase`. Before ASLR came along this was close to dead weight for executables, since they nearly always got the address they asked for. ASLR made it necessary all over again, because an image with no relocation data is an image that cannot be moved.
- `.tls` - Thread Local Storage, meaning the per-thread data a program sets aside for itself. It can also register callbacks, and those callbacks run before the entry point does.
- `.pdata` - exception handling and stack unwinding data, which is required on x64.
- `.debug` - debugging information, in the cases where it has not been stripped out into a separate PDB file.
- `.didat` - delay-loaded import data, for DLLs that get resolved on first use rather than at load time.

Names outside of that set are common enough and not really much to write home about on their own. Plenty of software uses custom sections for its own perfectly good reasons, and tools that rewrite an already-finished binary have a habit of naming whatever they add after themselves, which is where names like `UPX0`, `.aspack`, `.themida` and `.vmp0` come from.

### Overlay

Anything sitting past the end of the last section's raw data is not part of the image. The section table does not describe it, the loader does not map it, and as far as execution is concerned it may as well not be there at all. It is just bytes riding along at the end of the file.

This is where Authenticode signatures live, and it is also where self-extracting archives and installers keep their payload, so a large overlay is a completely normal thing to run into with certain kinds of software. Since no header describes the region in the first place, appending to the overlay changes no field and breaks no structure.

## Abuse

Everything up to this point has been about what each piece of the format is for. This part is about what tends to happen when somebody looks at those same pieces and sees an opportunity rather than a specification, because a tool that only understands the intended use of a field is going to be wrong about a surprising number of the files you point it at.

There is one idea sitting underneath nearly all of it. The Windows loader is a permissive thing. It reads a small handful of fields, ignores most of the rest, and puts up with a genuinely impressive amount of malformed structure, largely because refusing to run software that used to run is a far worse outcome for Microsoft than running something a little strange. An analysis tool tends to be the opposite. It is strict, because it was written from the specification rather than from watching what the loader actually does. Every place those two disagree is a place where something can be tucked away. Build a file the loader happily accepts but the parser rejects, or one the parser reads differently than the loader does, and the parser's output has quietly stopped describing the program that is actually going to run. That gap has a name in the literature, a parser differential, and a great deal of what follows is really just a specific instance of it.

The lists below include, but are not limited to, what is described. There is no complete version of this list and there never will be, because the set of things a format will tolerate is always going to be much larger than the set of things anyone has thought to go and try.

1. DOS Header

- The "MZ" magic gets removed entirely while everything else in the header is left perfectly intact. The file will not launch on its own anymore, and a tool keying on those first two bytes will not recognize it either, but a loader that maps the image by hand can put them back at runtime without any trouble at all.
- The magic gets swapped out for some other marker that a matching custom loader knows to look for, which quietly turns the payload into something only the intended loader is able to use.
- `e_lfanew` gets pointed deep into the file, so the real PE header ends up sitting a long way from the start with all sorts of unrelated content in between.
- `e_lfanew` gets set to a negative number. The field is signed, and a parser that stashes it in an unsigned type, or adds it to something without checking first, ends up with an offset that is either enormous or has quietly wrapped around.
- `e_lfanew` gets pointed back inside the 64-byte DOS header itself, which produces overlapping structures where the very same bytes are read as two entirely different things depending on who is doing the reading.
- Values get chosen that are aligned or bounded a little differently than a strict reader expects, on the fairly reasonable assumption that the loader will shrug and accept them while the reader will not.
- `e_res` and `e_res2` get filled with configuration, keys, campaign identifiers, or a marker of some kind. That is 28 bytes nothing validates, and they will survive every copy anyone ever makes of the file.
- The file gets built so that some other format's header is also perfectly valid at offset 0, or shortly after it, producing a polyglot that is simultaneously a valid executable and a valid archive or document depending entirely on which tool happens to open it.
- A DOS header gets copied verbatim out of a known-good Microsoft binary, so that every field lines up against something legitimate if anyone bothers to compare.
- The header gets left deliberately damaged in a way that crashes common parsers, working on the theory that a tool which cannot open the file is not going to report anything about it either.

2. DOS Stub

- The standard stub gets replaced outright with stored data. Nothing on any modern system executes it, nothing validates it, and it is big enough to be genuinely useful.
- `e_lfanew` gets inflated to open up a much larger gap between the DOS header and the PE signature than any normal stub would ever need, and then that cavity gets filled.
- An encrypted second stage or a configuration blob gets parked in that cavity, where it is not covered by any section and will not turn up in a scan that only walks sections.
- An author mark, handle, build tag or message gets left there. This is the oldest use anyone has ever found for the space and it is still far and away the most common one.
- The stub gets turned into a genuinely functional DOS program, so the file ends up behaving differently depending on which operating system opens it.
- The stub gets copied out of a legitimate signed binary, so that a byte-for-byte comparison against known-good software comes back clean.
- The stub gets padded out purely to change the file hash without changing a single thing about how the program behaves, which is enough on its own to defeat matching against exact-hash blocklists.
- A decoy PE header gets placed inside the stub region, so that a tool scanning forward looking for "PE\0\0" finds the wrong one first.

3. Rich Header

- It gets deleted, which takes the entire toolchain fingerprint along with it. The loader does not care in the slightest and the file runs exactly as it did before.
- It gets zeroed in place, leaving the space where it always was but destroying everything that used to be in it.
- A Rich header gets copied wholesale out of some unrelated binary, so that anyone clustering files by build environment ends up pointing at whoever built the donor file instead. This has been done deliberately to hang an operation on the wrong group.
- The XOR key and checksum get recomputed after editing, so the block stays internally consistent and passes validation, which makes a forged header considerably harder to tell apart from a real one.
- The space gets reused for storage once the original contents are gone, since it sits in that same unmapped gap as the stub and nothing is going to complain about it.
- It gets left completely intact by accident, which is not really an abuse so much as the reason anyone bothers reading it in the first place. It is routinely the last artifact still standing in a file that has otherwise been very carefully scrubbed.

4. COFF File Header

- `TimeDateStamp` gets backdated to place a build before some known event, or pushed forward to muddle the ordering within a set of samples.
- The timestamp gets zeroed out entirely, which removes the information but is a bit of a tell all by itself, since real toolchains very rarely produce a zero here.
- The timestamp field gets used as storage, since any 32-bit value at all is accepted. Version markers and campaign identifiers have both turned up sitting in there.
- A `NumberOfSections` gets declared that disagrees with the section headers actually present, so the loader and the parser end up walking different amounts of the table.
- A `Machine` value gets declared that does not match the architecture of the code actually in the file, which sends a disassembler happily off down the wrong instruction set.
- The DLL bit in `Characteristics` gets set or cleared so the same file can be run as an executable and loaded as a library, doing something different in each case.
- `SizeOfOptionalHeader` gets manipulated so the section table begins somewhere other than where a fixed-size assumption would put it, which shifts every section header a reader goes on to parse.
- The relocations-stripped flag gets set on a file that still contains a perfectly good relocation table, or the other way around.
- `PointerToSymbolTable` gets aimed at arbitrary content, since the field has been deprecated for images long enough that almost nothing bothers following it anymore.

5. Optional Header

- `AddressOfEntryPoint` gets pointed at a section that is not the code section, so execution begins somewhere a reader is not looking.
- A stub gets prepended to an otherwise completely legitimate program and the entry point gets repointed at it. This is the classic file infector pattern, and the original program is left intact and fully functional afterward, which is rather the whole point of it.
- The entry point gets set into a writable section, which is something code that rewrites itself needs by definition and which is close to meaningless in normally compiled software.
- `SizeOfImage` gets inflated well past what the sections actually require, reserving mapped space at runtime for a payload that does not exist anywhere in the file yet.
- `SizeOfHeaders` gets manipulated so the region between the end of the real headers and the first section comes out larger than it has any need to be, which opens up a gap in the mapped image that no section describes.
- ASLR, DEP or Control Flow Guard get switched off in `DllCharacteristics`, which is a requirement for anything depending on hardcoded addresses and is genuinely rare in software built this decade.
- `SectionAlignment` gets set below the page size, which drops the loader into a mode where the file is mapped flat and file offsets simply equal RVAs. It is entirely legal, it is close to unheard of in compiled software, and it breaks the address translation logic in any reader that assumed the normal case.
- `NumberOfRvaAndSizes` gets reduced below sixteen so the later data directories are not present as far as a reader is concerned, while the structures they point at are all still sitting there in the file.
- `Win32VersionValue` gets set to something nonzero, since it is reserved and ignored and therefore free real estate.
- `CheckSum` gets left at a value that does not match the file, which is completely normal for user-mode software and is exactly why it is useless as an integrity check.
- An unusual `ImageBase` gets chosen, which matters a great deal to anything that was written against a fixed address.

6. Data Directories

- Data gets appended inside the certificate table's declared length, so it is technically covered by the signature structure while not actually being part of what got hashed. A signed file ends up carrying content that whoever signed it never laid eyes on.
- A signature gets lifted from a legitimate file and attached. It will not validate, but it satisfies any check that only bothers asking whether a signature is present at all.
- A stolen or fraudulently obtained certificate gets used, which produces a file that validates correctly and is trusted by everything downstream of that check.
- The import directory gets pointed somewhere the section table does not cover, so the imports exist as far as the loader is concerned but not for a reader that is translating through sections.
- Almost no imports get declared and the rest are resolved at runtime by name, which leaves the import table describing a program that appears to do very little.
- A TLS directory with callbacks gets added, and those callbacks run before the entry point, which means they run before anyone watching the entry point has seen anything at all.
- A resource tree gets built that nests very deeply or refers back to itself, which exhausts a recursive parser rather than a person.
- Export forwarders get used to redirect calls into another library, turning the file into a proxy that passes legitimate traffic through while quietly doing something else alongside it.
- A CLR header gets added so the file is managed, moving the real logic into bytecode that a native disassembler is not going to show you.
- Handlers get registered through the load configuration table, which is what controls exception handling and Control Flow Guard behavior.
- A debug directory gets left behind pointing at a path or a symbol server that gives away rather more about the build environment than was intended.

7. Section Table

- A section gets marked both writable and executable, which a normal toolchain has essentially no reason to produce and which any code that decrypts itself in place absolutely requires.
- A `VirtualSize` gets declared far larger than `SizeOfRawData`, reserving zero-filled space at runtime to decompress into. This is about the most reliable structural indicator of packing there is.
- A `SizeOfRawData` gets declared larger than the virtual size, so the surplus bytes exist in the file but never get mapped and never execute, which makes them storage rather than code.
- Two sections get their virtual ranges overlapped, so the mapped result depends on the order the loader processes them in and does not match a reader that treats sections as neatly distinct.
- Sections get listed out of virtual address order, which breaks readers that assume the table arrives sorted and can be used to build a translation table that resolves differently than the loader's does.
- A section's raw data gets pointed into the header region, so the same bytes belong to two structures at once.
- Sections get named after ordinary compiler output while being given flags that contradict the name entirely, since the loader routes on flags and people route on names.
- A section gets added to an existing legitimate file and the entry point gets repointed at it, leaving the original program untouched so it still behaves perfectly normally when run.
- Names get used that are not NUL-terminated, not ASCII, or that reference the string table in an image where no string table exists, all of which produce garbage in a tool that prints names without validating them first.
- Zero sections get declared, or a count right up near the loader's limit of ninety-six, both of which sit at the edges of what readers tend to get tested against.

8. The Sections Themselves

- `.text` gets patched. The padding a compiler leaves between functions is often big enough for a small amount of code, and everything around it is real compiled output, so scanning the section as a whole turns up nothing much out of the ordinary.
- `.text` is also where instruction sequences get harvested for control-flow attacks against other programs, which is precisely what the mitigations over in `DllCharacteristics` exist to make harder.
- `.rdata` ends up carrying obfuscated strings and encrypted configuration, because it is read-only, thoroughly unremarkable, and the place a reader already expects to find constants sitting anyway.
- `.data` becomes the staging area for a decrypted payload, so its flags say more about it than its name does.
- `.bss` has no bytes in the file whatsoever, only a reserved size, so a buffer that only ever exists at runtime leaves nothing at all on disk to find.
- `.rsrc` holds embedded executables, encrypted stages and configuration, and it does so comfortably, because resources are arbitrary bytes by design and a large binary resource is a completely normal thing to run into.
- `.rsrc` is also where the icons and version information live that make a file look like software from a vendor it has nothing to do with, which is about the cheapest impersonation the format has to offer.
- `.reloc` gets stripped and its space reused, since relocation data is dense, deeply uninteresting to read through, and rarely inspected by anybody.
- `.tls` is the pre-entry execution slot, which makes it useful for unpacking and for anti-analysis checks that want to run before a debugger set to break at the entry point has ever had a chance to stop.
- Sections carrying the names of known packers are really just the tool announcing itself, and their absence proves nothing at all, since renaming them is trivial.

9. Overlay

- A payload, an archive, or an entire second executable gets appended after the last section, which requires modifying no header and invalidates nothing.
- Something gets appended after a valid signature, so the file carries on verifying while hauling around content that was never signed.
- The file gets padded out to an enormous size, because a good number of scanning pipelines skip anything past a size threshold and a mostly empty two hundred megabyte file is very cheap to produce.
- Configuration gets stored that the program reads back out of its own file at runtime, which keeps it out of the mapped image entirely.
- An encrypted stage gets stored that only ever gets decrypted in memory, so the bytes sitting on disk have no recognizable structure to them.
- Data gets hidden inside a legitimate overlay, such as within the resources of an installer that genuinely does need a large overlay of its own.
- The overlay gets used to make every copy of the file unique, which defeats hash matching without touching a single byte of the actual program.

10. Against the Parser Itself

This last category does not go after the operating system at all. It goes after whatever is reading the file, which in our case means this program.

- Counts and sizes get declared far larger than the file itself, aimed squarely at a reader that allocates before it validates.
- Offsets and lengths get chosen so their sum overflows, so a bounds check written as `offset + size <= len` passes on arithmetic that has already quietly wrapped.
- Structures get made to point at themselves or form a cycle, so a reader that follows links without keeping track of where it has already been never actually stops.
- Nesting gets made deep enough to exhaust the stack in a reader that recurses.
- Tables get built that can be walked forever without consuming any input, so a loop that assumes it is making progress does not.
- Strings get left without terminators, so a reader hunting for a NUL runs all the way to the end of the buffer.
- Any structure at all gets placed where reading it requires an out-of-bounds access, since in most implementations that is either a crash or a read of memory that was never part of the file to begin with.

A crash in this last category is not really a bug in the ordinary sense of the word. What it means is that the file being examined successfully put a stop to the examination, which is an outcome the author of that file would be perfectly happy with. That is why nothing in this program trusts a number that came out of a file, and why the limit and overflow cases get treated as evidence of intent rather than as ordinary malformation.

## Chapters

Big-Endianess & Little-Endianess


## Chapter Something - ByteReader

This particular issue deserves its very own special section. You'll recognize later down the line that we need to talk about this. In my previous iterations of this program (although named differently), we parsed bytes, but nothing else. We never "checked" the bytes, or performed boundary checks. The generalized rule that I had to implement was that we should never trust bytes as they come. This sounds weird, but it will make sense.

Bytes by themselves are essentially nothing without something to interpret them. A byte is eight bits, a number somewhere between 0 and 255, and that is genuinely the whole of what it is. Everything else we ever say about one, that it is a character, a length, an opcode, arrives from whatever is doing the reading rather than from the byte itself.

Take 0xCC, which you will run into constantly in compiled Windows code. Sitting in `.rdata` it is the number 204. Sitting in the middle of a string it is a stray high byte. Sitting in `.text` at the exact position the processor begins decoding an instruction, it is `INT3`, the one-byte software breakpoint, and it raises a breakpoint exception the moment it runs. Same byte in all three cases, and the meaning came entirely from the context it was read in. That is the idea this whole chapter is built on.

The CPU is the interpreter here, and it is not a thoughtful one. It never stops to consider whether 0xCC was meant as code. The instruction pointer (`RIP` on x86-64) holds an address, the fetch unit pulls bytes from memory at that address, the decoder turns them into an instruction, and it runs. Then the pointer moves along and the whole thing happens again. The registers hold the operands and the results of that work rather than the instructions themselves, and there is no way on x86-64 to execute the contents of a register. Execution always comes out of memory, at whatever address the instruction pointer happens to be holding.

Now, why would a compiler fill the gaps between functions with a breakpoint of all things? Because it fails loudly. Control flow is never supposed to reach that padding, so if something goes wrong and it does, the program stops immediately rather than drifting through whatever bytes sit between one function and the next. That is Microsoft's toolchain specifically. GCC and Clang make the same decision differently and pad with NOPs, usually the multi-byte encodings that let them fill an exact number of bytes with a single instruction. Across a PE as a whole the most common byte is not 0xCC at all, it is 0x00, since alignment padding and unused header fields are all zeros.

Here is the part that makes "untrusted" mechanical rather than philosophical. An x86-64 instruction runs anywhere from one byte to fifteen, and nothing in the byte stream marks where any of them begin. An instruction starts where the decoder starts, and that is the only thing that decides it. Point a decoder one byte later than the real boundary and you do not get an error, you get a completely different run of perfectly valid instructions that has nothing to do with what the program actually executes. Anti-disassembly tricks live entirely in that gap. For our purposes it means the bytes never carry their own structure. We supply the structure, and we are perfectly capable of supplying the wrong one.

Next is the check on the boundary, and this is where I had it wrong when I first wrote this out. exi opens a file and reads it into a `Vec<u8>` on the heap, and that vector is the entire world as far as the parser is concerned. When the DOS header tells us the PE signature sits at `e_lfanew`, that value is a number an author chose, and our job before touching it is to ask whether that offset and the four bytes we want to read from it both land inside a buffer that is `data.len()` bytes long. That is the bounds check in full. It compares a file-derived offset against the length of a buffer we allocated ourselves.

Pages have nothing to do with it, and I want to be straight about that because I had written the opposite. A page is the unit the operating system manages virtual memory in, normally 4096 bytes on x86-64, and it is the granularity at which the kernel hands out memory and sets permissions. The MMU is not a separate thing off doing its own business alongside the kernel, it is the hardware half of the same mechanism. The kernel builds the page tables, the MMU walks them on memory accesses to turn a virtual address into a physical one, the TLB caches those translations so the walk does not have to happen every single time, and a page fault is what the MMU raises when the translation is missing or the permissions do not match what was attempted. All of that is real and none of it is what our bounds check is doing.

The reason it is not is that the file we are examining never gets loaded. It is data. It is a few hundred kilobytes sitting in our heap that we read, index into, and interpret. Nothing in it is mapped, nothing in it is executable, and none of its RVAs point anywhere at all, because an RVA describes a layout that only comes into existence once the Windows loader maps the image, which is a thing this program deliberately never does. There are two programs in the room and it is easy to blur them together. exi is running and has pages of its own. The PE we are reading is inert. The bounds check is protecting the first one from the second.

So what does a failed check actually protect us from? Not from reading somebody else's memory, which is the answer you would expect and is not the right one. Rust has already handled that part: `data[a..b]` past the end of the buffer panics rather than reading through it, so the memory safety violation was never on the table to begin with. What a panic does instead is take the whole process down, and a process going down is a file that successfully stopped the tool inspecting it. Our explicit check earns us a `ParseError` in place of that. We notice the structure runs past the end, we record it as `OutOfBounds` or `TruncatedHeader`, and we carry on parsing the rest of the file and still hand back a report.

The arithmetic follows the same reasoning. A check written as `offset + size <= data.len()` looks correct and is not, because a large enough pair of values wraps around before the comparison ever happens and a small number comes out the other side, quietly passing a check on bytes that are nowhere near the buffer. So the additions go through `checked_add`, and a wrap is not a near miss we recover from silently. It becomes `IntegerOverflow` and it gets reported, because nothing a real compiler emits has offsets that sum past the end of a 64-bit integer. A count field works the same way. A table declaring four billion entries gets refused against `limits.rs` before it ever reaches an allocation rather than after.

The thing I was originally reaching for with pages is real, it simply belongs to a different discussion. When the loader maps a section it maps whole pages, so a section whose contents do not fill a multiple of 4096 leaves the remainder of that last page zero-filled. Sections get padded on disk too, out to `FileAlignment`, so a section carrying 700 bytes of content takes up 1024 on disk and the leftovers exist in the file while doing nothing whatsoever. The gaps between functions inside `.text` are the same story at a smaller scale.

Those gaps have a name, code caves, and they do get used. What they are not is somewhere malware sits waiting on its own. Ten bytes is not a program, it is a trampoline. A near `jmp rel32` is 5 bytes, a `push imm32` followed by `ret` is 6, and loading a full 64-bit address into a register and jumping to it comes to 12. That is enough to send execution somewhere else and it does absolutely nothing until something transfers control into it. Bytes in a cave are inert in exactly the way every other byte in the file is inert.

The version of this that matters to a static tool is the on-disk slack rather than the runtime slack, since the loader zero-fills the mapped remainder while the file-alignment padding is bytes we can actually go and read. `SizeOfRawData` exceeding `VirtualSize` is the structural form of it, which is already sitting up in the Abuse list, and finding those regions is a feature this program ought to have rather than something the bounds check hands us for free. The bounds check is doing one job, and it is a smaller and more boring job than I originally gave it credit for. It makes sure that every read we perform is a read of bytes that actually exist.