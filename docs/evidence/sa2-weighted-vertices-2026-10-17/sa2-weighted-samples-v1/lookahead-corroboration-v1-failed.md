# Lookahead corroboration V1 failure

The one V1 run stopped before original-word checking and file-window coverage. `int(value, 0)` rejected the native audit CSV's bare hexadecimal word `7c0802a6` with `ValueError: invalid literal for int() with base 0`.

The V1 script is preserved. V2 reads that instruction-word column with explicit base16. This was a reader schema error; no native-code failure, packet data mismatch, engine execution or source mutation occurred. The earlier completed weighted packet inventory remains passed.
