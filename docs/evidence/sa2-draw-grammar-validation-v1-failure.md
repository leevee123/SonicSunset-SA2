# Validation v1 selection failure

The once-only v1 run reached cache candidate selection, then stopped with `StopIteration`: it wrongly assumed that at least one cache call had exactly one same-index definition candidate in the file. This is a validation-script selection failure, not a failure of the original parser or sample. No completed validation result was written.

Version 2 will choose an explicitly identified candidate body for the hypothetical control trace and retain all ambiguous same-index candidates in the complete CSV. Such a trace cannot establish runtime cache selection or order.
