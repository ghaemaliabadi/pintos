# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(encryption-test) begin
PintOS File Encryption Test
==========================
Testing basic file encryption...
✓ File is initially unencrypted
✓ Encryption enabled successfully
✓ File is now encrypted
✓ Successfully unlocked with correct password
✓ Data integrity verified after encryption/decryption
All encryption tests passed!

✓ All tests completed successfully!
(encryption-test) end
encryption-test: exit(0)
EOF
pass;