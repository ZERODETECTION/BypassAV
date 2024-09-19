from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

def encrypt_hex_content(file_path, key, output_file):
    try:
        # Open the file in binary mode
        with open(file_path, 'rb') as pe_file:
            content = pe_file.read()

        # Convert content to hex
        hex_content = content.hex()

        # Prepare AES encryption
        cipher = AES.new(key, AES.MODE_EAX)  # EAX mode provides both encryption and authentication
        ciphertext, tag = cipher.encrypt_and_digest(hex_content.encode())

        # Write the results to the output file
        with open(output_file, 'wb') as out_file:
            out_file.write(cipher.nonce)  # Write nonce
            out_file.write(tag)           # Write tag
            out_file.write(ciphertext)    # Write encrypted data

        print(f"Encrypted data saved to '{output_file}'")
    
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
pe_file_path = "input.bin"  # Replace with the path to your PE file
output_file = "out.aes"            # Output file to save the encrypted data
key = get_random_bytes(16)         # AES requires a key of 16, 24, or 32 bytes

# Formatiere die Bytes im gewünschten C-Array-Stil
formatted_output = ", ".join(f"0x{byte:02x}" for byte in key)

# Gib die Ausgabe in der gewünschten Form aus
print(f"char key[] = {{ {formatted_output} }};")

encrypt_hex_content(pe_file_path, key, output_file)
