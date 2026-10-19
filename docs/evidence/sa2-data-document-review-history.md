# Documentation review line endings

V1 prepared the topic titles, directory update and review patches, then stopped because Windows write_text saved two new history reports as CRLF while the helper expected hashes of LF input strings. This changed only scratch documentation; the repository, engine and test package were untouched. The failed helper is preserved. V2 hashes actual saved bytes and checks all original evidence copies, unchanged staged files and source/preimage guards.
