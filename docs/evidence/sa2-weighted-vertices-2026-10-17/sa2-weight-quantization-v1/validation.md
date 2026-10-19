# GQR1 weight conversion validation

One run passed: all65,536 signed16 words map exactly to n/256 as binary32, with65,535 normal values and one positive zero, no negative zero, subnormal, nonfinite or rounding mismatch. Original helper source/words and PSQ fields are verified; the helper writes GQR1 once and does not save/restore it before its normal return. This is an explicit math contract, not observed live GQR0 or complete weighted transformation. Full per-input bits and source addresses/digests remain in CSV/AI twin.
