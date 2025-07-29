/* Test basic encryption functionality */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char *argv[])
{
    const char *test_filename = "test_encrypt_file.txt";
    const char *password = "test123";
    const char *new_password = "newpass456";
    const char *test_content = "This is a test file for encryption.";
    
    printf ("Starting encryption test...\n");
    
    /* Create a test file */
    if (!create (test_filename, strlen(test_content))) {
        printf ("Failed to create test file\n");
        return 1;
    }
    
    /* Write some content to the file */
    int fd = open (test_filename);
    if (fd == -1) {
        printf ("Failed to open test file\n");
        return 1;
    }
    
    if (write (fd, test_content, strlen(test_content)) != (int)strlen(test_content)) {
        printf ("Failed to write to test file\n");
        close (fd);
        return 1;
    }
    close (fd);
    
    /* Test: Check if file is initially not encrypted */
    if (is_file_encrypted (test_filename)) {
        printf ("ERROR: File should not be encrypted initially\n");
        return 1;
    }
    printf ("PASS: File is not encrypted initially\n");
    
    /* Test: Encrypt the file */
    if (!encrypt_file (test_filename, password)) {
        printf ("ERROR: Failed to encrypt file\n");
        return 1;
    }
    printf ("PASS: File encrypted successfully\n");
    
    /* Test: Check if file is now encrypted */
    if (!is_file_encrypted (test_filename)) {
        printf ("ERROR: File should be encrypted now\n");
        return 1;
    }
    printf ("PASS: File is encrypted\n");
    
    /* Test: Try to encrypt already encrypted file (should fail) */
    if (encrypt_file (test_filename, password)) {
        printf ("ERROR: Should not be able to encrypt already encrypted file\n");
        return 1;
    }
    printf ("PASS: Cannot encrypt already encrypted file\n");
    
    /* Test: Change password */
    if (!change_file_password (test_filename, password, new_password)) {
        printf ("ERROR: Failed to change file password\n");
        return 1;
    }
    printf ("PASS: Password changed successfully\n");
    
    /* Test: File should still be encrypted after password change */
    if (!is_file_encrypted (test_filename)) {
        printf ("ERROR: File should still be encrypted after password change\n");
        return 1;
    }
    printf ("PASS: File still encrypted after password change\n");
    
    /* Clean up */
    remove (test_filename);
    
    printf ("All encryption tests passed!\n");
    return 0;
}