# Inspection v1 graph-classification guard

The once-only v1 inspection stopped before writing completed evidence because it assumed every frozen direct-call graph row must be a native branch with its link bit set. Frozen analysis references can include a different native transfer classification. The original script is preserved; no original bytes or analysis source changed.

Version2 will retain the graph reference and separately expose original target, link bit and agreement, without inferring missing native effects.
