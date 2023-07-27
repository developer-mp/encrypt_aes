#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 128          // AES-128
#define KEY_SIZE AES_KEY_SIZE / 8 // AES-128 requires 128-bit key (16 bytes)
#define BUFFER_SIZE 4096

int main()
{
    unsigned char key[KEY_SIZE];

    // seed the PRNG (Pseudo-Random Number Generator) with random data
    if (RAND_poll() != 1)
    {
        fprintf(stderr, "Error seeding the PRNG\n");
        return 1;
    }

    // ask the user for input file path
    char input_file_path[256];

    printf("Enter the path of the input file: ");
    scanf("%255s", input_file_path); // 255 ensures that the input won't exceed the array size

    // generate a random key
    if (RAND_bytes(key, KEY_SIZE) != 1)
    {
        fprintf(stderr, "Error generating random key\n");
        return 1;
    }

    // print the encryption key
    printf("Encryption key: ");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x", key[i]);
    }
    printf("\n");

    // calculate the output file path with "_encrypted" postfix
    char output_file_path[256];
    char *dot = strrchr(input_file_path, '.'); // find the last dot in the input file path
    if (dot)
    {
        // if a dot is found, append "_encrypted" before the extension
        snprintf(output_file_path, sizeof(output_file_path), "%.*s_encrypted%s", (int)(dot - input_file_path), input_file_path, dot);
    }
    else
    {
        // if no dot is found, append "_encrypted" at the end of the input file path
        snprintf(output_file_path, sizeof(output_file_path), "%s_encrypted", input_file_path);
    }

    FILE *input_file = fopen(input_file_path, "rb");
    FILE *output_file = fopen(output_file_path, "wb");

    if (!input_file || !output_file)
    {
        fprintf(stderr, "Error opening input or output file\n");
        return 1;
    }

    unsigned char buffer_in[BUFFER_SIZE];
    unsigned char buffer_out[BUFFER_SIZE];

    // initialize the encryption context
    EVP_CIPHER_CTX *encrypt_ctx = EVP_CIPHER_CTX_new();
    if (!encrypt_ctx)
    {
        fprintf(stderr, "Error initializing encryption context\n");
        return 1;
    }

    // set the encryption key and IV (Initialization Vector)
    if (EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_128_cbc(), NULL, key, NULL) != 1)
    {
        fprintf(stderr, "Error setting encryption key and IV\n");
        EVP_CIPHER_CTX_free(encrypt_ctx);
        return 1;
    }

    // encrypt the file
    int bytes_read, bytes_written;
    while ((bytes_read = fread(buffer_in, 1, BUFFER_SIZE, input_file)) > 0)
    {
        if (EVP_EncryptUpdate(encrypt_ctx, buffer_out, &bytes_written, buffer_in, bytes_read) != 1)
        {
            fprintf(stderr, "Error encrypting data\n");
            EVP_CIPHER_CTX_free(encrypt_ctx);
            return 1;
        }
        fwrite(buffer_out, 1, bytes_written, output_file);
    }

    // finalize the encryption
    if (EVP_EncryptFinal_ex(encrypt_ctx, buffer_out, &bytes_written) != 1)
    {
        fprintf(stderr, "Error finalizing encryption\n");
        EVP_CIPHER_CTX_free(encrypt_ctx);
        return 1;
    }
    fwrite(buffer_out, 1, bytes_written, output_file);

    // cleanup the encryption context
    EVP_CIPHER_CTX_free(encrypt_ctx);

    fclose(input_file);
    fclose(output_file);
    printf("Encryption successful\n");

    return 0;
}
