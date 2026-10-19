# Independent weighted cross-check

All 82144 per-lane arithmetic rows reduce to 57802 distinct operation/operand cases. Every exact-rational result bit matches independent CRT fused float arithmetic or an exact binary64 product rounded to float. No differences were found. Original/frozen/primary-source inputs at 14 paths rehash unchanged.

Weighted fused cancellation is B0000000, while separately rounded weighted multiplication plus the old value would be zero. Transform-before-weight fused cancellation is A8000000. Zero-weight accumulation still performs final FTZ and signed-zero behavior: 00000000/80000000/00000000/00000000/80000000/00000000. Duplicate-destination order examples produce zero forward and one reversed in modes1 and2; nonzero modes1,2,127 agree for identical inputs. No weight-zero shortcut, normalization or reordered reduction was substituted. Full values and traces remain in the oracle artifacts.
