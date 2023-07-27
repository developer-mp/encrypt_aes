#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define AES_KEY_SIZE 128          // AES-128
#define KEY_SIZE AES_KEY_SIZE / 8 // AES-128 requires 128-bit key (16 bytes)
#define BUFFER_SIZE 4096

// function to convert hexadecimal string to binary data
int hex_string_to_binary(const char *hex_string, unsigned char *binary_data, size_t binary_data_len)
{
    size_t hex_string_len = strlen(hex_string);
    if (hex_string_len % 2 != 0 || hex_string_len / 2 != binary_data_len)
    {
        return 0; // invalid input length
    }

    for (size_t i = 0; i < hex_string_len; i += 2)
    {
        int ret = sscanf(hex_string + i, "%2hhx", &binary_data[i / 2]);
        if (ret != 1)
        {
            return 0; // conversion error
        }
    }

    return 1; // conversion successful
}

int main()
{
    unsigned char key[KEY_SIZE];

    // ask the user for the path of the encrypted file
    char input_file_path[256];

    printf("Enter the path of the encrypted file: ");
    scanf("%255s", input_file_path); // 255 ensures that the input won't exceed the array size

    // ask the user for the encryption key as a string
    char encryption_key_string[33]; // 32 hexadecimal characters + null terminator

    printf("Enter the encryption key: ");
    scanf("%32s", encryption_key_string);

    // convert the encryption key string to binary data
    if (!hex_string_to_binary(encryption_key_string, key, KEY_SIZE))
    {
        fprintf(stderr, "Error reading encryption key\n");
        return 1;
    }

    // calculate the output file path with "_decrypted" postfix
    char output_file_path[256];
    const char *encrypted_pos = strstr(input_file_path, "encrypted");
    if (encrypted_pos)
    {
        size_t pos = encrypted_pos - input_file_path;
        snprintf(output_file_path, sizeof(output_file_path), "%.*sdecrypted%s", (int)pos, input_file_path, encrypted_pos + strlen("encrypted"));
    }
    else
    {
        // if "encrypted" is not found in the input file path, append "_decrypted" at the end
        snprintf(output_file_path, sizeof(output_file_path), "%s_decrypted", input_file_path);
    }

    FILE *input_file = fopen(input_file_path, "r");
    FILE *output_file = fopen(output_file_path, "wb");

    if (!input_file || !output_file)
    {
        fprintf(stderr, "Error opening input or output file\n");
        return 1;
    }

    unsigned char buffer_in[BUFFER_SIZE];
    unsigned char buffer_out[BUFFER_SIZE];

    // initialize the decryption context
    EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!decrypt_ctx)
    {
        fprintf(stderr, "Error initializing decryption context\n");
        return 1;
    }

    // set the decryption key and IV (Initialization Vector)
    if (EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_128_cbc(), NULL, key, NULL) != 1)
    {
        fprintf(stderr, "Error setting decryption key and IV\n");
        EVP_CIPHER_CTX_free(decrypt_ctx);
        return 1;
    }

    // decrypt the file
    int bytes_read, bytes_written;
    while ((bytes_read = fread(buffer_in, 1, BUFFER_SIZE, input_file)) > 0)
    {
        if (EVP_DecryptUpdate(decrypt_ctx, buffer_out, &bytes_written, buffer_in, bytes_read) != 1)
        {
            fprintf(stderr, "Error decrypting data\n");
            EVP_CIPHER_CTX_free(decrypt_ctx);
            return 1;
        }
        fwrite(buffer_out, 1, bytes_written, output_file);
    }

    // finalize the decryption
    if (EVP_DecryptFinal_ex(decrypt_ctx, buffer_out, &bytes_written) != 1)
    {
        fprintf(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(decrypt_ctx);
        return 1;
    }
    fwrite(buffer_out, 1, bytes_written, output_file);

    // cleanup the decryption context
    EVP_CIPHER_CTX_free(decrypt_ctx);

    fclose(input_file);
    fclose(output_file);

    printf("Decryption successful\n", output_file_path);

    return 0;
}
