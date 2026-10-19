# Shared register-helper transport

Verified 12 original helper words. Both helpers preserve GPR3 through GPR7. The save helper writes saved registers to the caller-provided frame; the restore helper reloads them. Generated C pair-return reconstruction and dropped return modes are not substituted for this original register flow. Source hashes remain unchanged.
