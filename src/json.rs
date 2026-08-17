// TODO: Architecture is a nested enum (family + width), so serde will emit it
// as {"X86":"Bits64"} by default. Use a serde attribute here to flatten it to
// the Display form ("x86-64") before this goes anywhere user-facing.
