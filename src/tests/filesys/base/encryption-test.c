/* Test program for file encryption functionality */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>

const char *test_filename = "encryption_test.txt";
const char *test_password = "test123";
const char *test_data = "This is a test message that will be encrypted!";

static void
test_basic_encryption (void)
{
  printf ("Testing basic file encryption...\n");
  
  /* Create a test file */
  if (!create (test_filename, 0))
    {
      printf ("Failed to create test file\n");
      exit (1);
    }
  
  /* Open the file */
  int fd = open (test_filename);
  if (fd < 0)
    {
      printf ("Failed to open test file\n");
      exit (1);
    }
  
  /* Write test data */
  int bytes_written = write (fd, test_data, strlen (test_data));
  if (bytes_written != (int) strlen (test_data))
    {
      printf ("Failed to write test data: wrote %d bytes, expected %d\n",
              bytes_written, (int) strlen (test_data));
      close (fd);
      exit (1);
    }
  
  /* Test that file is not encrypted initially */
  if (is_encrypted (fd))
    {
      printf ("ERROR: File reports as encrypted before encryption\n");
      close (fd);
      exit (1);
    }
  printf ("✓ File is initially unencrypted\n");
  
  /* Enable encryption */
  if (!encrypt_file (fd, test_password))
    {
      printf ("Failed to enable encryption\n");
      close (fd);
      exit (1);
    }
  printf ("✓ Encryption enabled successfully\n");
  
  /* Verify file is now encrypted */
  if (!is_encrypted (fd))
    {
      printf ("ERROR: File not reported as encrypted after encryption\n");
      close (fd);
      exit (1);
    }
  printf ("✓ File is now encrypted\n");
  
  /* Test reading encrypted data with correct password */
  if (!decrypt_file (fd, test_password))
    {
      printf ("Failed to decrypt file with correct password\n");
      close (fd);
      exit (1);
    }
  printf ("✓ Successfully unlocked with correct password\n");
  
  /* Read back the data */
  seek (fd, 0);
  char read_buffer[100];
  int bytes_read = read (fd, read_buffer, sizeof (read_buffer) - 1);
  if (bytes_read < 0)
    {
      printf ("Failed to read decrypted data\n");
      close (fd);
      exit (1);
    }
  
  read_buffer[bytes_read] = '\0';
  if (strcmp (read_buffer, test_data) != 0)
    {
      printf ("Data mismatch after encryption/decryption\n");
      printf ("Expected: %s\n", test_data);
      printf ("Got: %s\n", read_buffer);
      close (fd);
      exit (1);
    }
  printf ("✓ Data integrity verified after encryption/decryption\n");
  
  close (fd);
  remove (test_filename);
  
  printf ("All encryption tests passed!\n");
}

int
main (void)
{
  printf ("PintOS File Encryption Test\n");
  printf ("==========================\n");
  
  test_basic_encryption ();
  
  printf ("\n✓ All tests completed successfully!\n");
  return 0;
}