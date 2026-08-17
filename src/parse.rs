use crate::errors::{Anomaly, Format, ParseError, ParseResult};
use crate::reader::Bytes;

/*
    Format detection and dispatch.

    This file does not read structures itself. Its job is to look at the very
    front of a buffer, decide which container we are holding, and hand the
    work to the module that knows that container. reader.rs supplies the
    bounds-checked cursor that all of those modules read through, since the
    "are these bytes actually there" question is identical no matter whose
    format we end up parsing.

    Detection has to stay cheap and it has to stay suspicious. We are reading
    a handful of bytes to pick a branch, and a file is allowed to look like
    two things at once, so the answer is not always a single format.
*/
