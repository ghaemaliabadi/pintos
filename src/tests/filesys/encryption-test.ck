# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
Starting encryption test...
PASS: File is not encrypted initially
PASS: File encrypted successfully
PASS: File is encrypted
PASS: Cannot encrypt already encrypted file
PASS: Password changed successfully
PASS: File still encrypted after password change
All encryption tests passed!
EOF
pass;