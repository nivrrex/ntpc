/*
 * 项目名称: 跨平台高精度 NTP 同步工具 (v0.3)
 * 编译环境: Windows (MinGW-gcc) 或 Linux (gcc)
 * 更新日志 v0.3:
 * - [修复] 原始时间戳验证逻辑错误（应比对transmit timestamp）
 * - [优化] 改进调试输出，便于诊断网络问题
 * 
 * [编译命令]
 * Linux:   gcc ntp_sync.c -o ntp_sync -lm
 * Windows: gcc ntp_sync.c -o ntp_sync.exe -lws2_32
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_NET_ERROR() WSAGetLastError()
    #define IS_INVALID_SOCKET(s) ((s) == INVALID_SOCKET)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <errno.h>
    typedef int socket_t;
    #define CLOSE_SOCKET(s) close(s)
    #define GET_NET_ERROR() (errno)
    #define IS_INVALID_SOCKET(s) ((s) < 0)
#endif

#define NTP_PORT 123
#define NTP_PACKET_SIZE 48
#define NTP_TIMEOUT_SEC 5
#define NTP_TIMESTAMP_DELTA 2208988800ull
#define MAX_HOSTNAME_LEN 255
#define MAX_SAMPLES 5
#define MIN_VALID_STRATUM 1
#define MAX_VALID_STRATUM 15

/* 内置 NTP 服务器池 */
const char* INTERNAL_NTP_SERVERS[] = {
    "ntp.aliyun.com",
    "time.cloudflare.com",
    "pool.ntp.org"
};
const int INTERNAL_SERVER_COUNT = 3;

/* 错误码定义 */
typedef enum {
    NTP_SUCCESS = 0,
    NTP_ERR_DNS_FAILED,
    NTP_ERR_SOCKET_CREATE,
    NTP_ERR_SEND_FAILED,
    NTP_ERR_RECV_TIMEOUT,
    NTP_ERR_INVALID_RESPONSE,
    NTP_ERR_INVALID_STRATUM,
    NTP_ERR_SET_TIME_FAILED,
    NTP_ERR_PERMISSION_DENIED,
    NTP_ERR_INVALID_HOSTNAME
} ntp_error_t;

const char* ntp_error_strings[] = {
    "成功",
    "DNS解析失败",
    "Socket创建失败",
    "发送请求失败",
    "接收响应超时",
    "无效的NTP响应",
    "无效的Stratum值",
    "设置系统时间失败",
    "权限不足",
    "无效的主机名"
};

#pragma pack(push, 1)
typedef struct {
    uint8_t li_vn_mode;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;
    uint32_t ref_ts_sec;
    uint32_t ref_ts_frac;
    uint32_t orig_ts_sec;
    uint32_t orig_ts_frac;
    uint32_t recv_ts_sec;
    uint32_t recv_ts_frac;
    uint32_t trans_ts_sec;
    uint32_t trans_ts_frac;
} ntp_packet;
#pragma pack(pop)

typedef struct {
    double corrected_time;
    double delay;
    ntp_error_t error;
} ntp_result;

/* --- 网络初始化 --- */
int init_networking() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[错误] Winsock 初始化失败\n");
        return 0;
    }
#endif
    return 1;
}

void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* --- 高精度时间戳获取 --- */
double get_local_time_double() {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned __int64 val = ((unsigned __int64)ft.dwHighDateTime << 32) + ft.dwLowDateTime;
    return (double)(val - 116444736000000000ULL) / 10000000.0;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
#endif
}

/* --- 主机名验证 --- */
int validate_hostname(const char* hostname) {
    if (!hostname || strlen(hostname) == 0 || strlen(hostname) > MAX_HOSTNAME_LEN) {
        return 0;
    }
    /* 基本格式检查：只允许字母、数字、点、横线 */
    for (const char* p = hostname; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || 
              (*p >= 'A' && *p <= 'Z') || 
              (*p >= '0' && *p <= '9') || 
              *p == '.' || *p == '-')) {
            return 0;
        }
    }
    return 1;
}

/* --- NTP 响应验证 --- */
int validate_ntp_response(const ntp_packet* packet, uint32_t sent_sec, uint32_t sent_frac) {
    /* 检查 mode（应为 4 = 服务器响应） */
    uint8_t mode = packet->li_vn_mode & 0x07;
    if (mode != 4 && mode != 5) { /* 4=server, 5=broadcast */
        fprintf(stderr, "[调试] 响应mode错误: %d (期望4或5)\n", mode);
        return 0;
    }

    /* 检查 stratum（1-15有效，0表示未同步） */
    if (packet->stratum == 0) {
        fprintf(stderr, "[调试] 服务器未同步 (stratum=0)\n");
        return 0;
    }
    if (packet->stratum > MAX_VALID_STRATUM) {
        fprintf(stderr, "[调试] Stratum值无效: %d\n", packet->stratum);
        return 0;
    }

    /* 验证服务器回显的原始时间戳（应等于客户端发送时间戳） */
    uint32_t resp_orig_sec = ntohl(packet->orig_ts_sec);
    uint32_t resp_orig_frac = ntohl(packet->orig_ts_frac);
    
    /* 允许小的时间戳差异（某些服务器实现可能不完全精确） */
    int sec_diff = abs((int)resp_orig_sec - (int)sent_sec);
    if (sec_diff > 1) {
        fprintf(stderr, "[调试] 原始时间戳秒差异过大: %d (发送:%u 回显:%u)\n", 
                sec_diff, sent_sec, resp_orig_sec);
        return 0;
    }

    /* 检查传输时间戳非零 */
    if (ntohl(packet->trans_ts_sec) == 0) {
        fprintf(stderr, "[调试] 传输时间戳为零\n");
        return 0;
    }

    return 1;
}

/* --- 设置系统时间 --- */
ntp_error_t set_system_time_platform(double new_time_seconds) {
    time_t sec = (time_t)new_time_seconds;
    double frac = new_time_seconds - (double)sec;

#ifdef _WIN32
    SYSTEMTIME st;
    ULONGLONG win_ticks = ((ULONGLONG)sec + 11644473600LL) * 10000000ULL + 
                          (ULONGLONG)(frac * 10000000ULL);
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(win_ticks & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(win_ticks >> 32);
    FileTimeToSystemTime(&ft, &st);

    if (!SetSystemTime(&st)) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            return NTP_ERR_PERMISSION_DENIED;
        }
        return NTP_ERR_SET_TIME_FAILED;
    }
#else
    if (getuid() != 0) {
        return NTP_ERR_PERMISSION_DENIED;
    }
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = (suseconds_t)(frac * 1000000.0);
    if (settimeofday(&tv, NULL) < 0) {
        return NTP_ERR_SET_TIME_FAILED;
    }
#endif
    return NTP_SUCCESS;
}

/* --- 单次 NTP 同步（不设置时间） --- */
ntp_result query_ntp_server(const char* hostname) {
    ntp_result result = {0.0, 0.0, NTP_ERR_DNS_FAILED};
    socket_t sock = -1;
    struct addrinfo hints, *res = NULL;
    ntp_packet packet = {0};

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(hostname, "123", &hints, &res) != 0) {
        return result;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (IS_INVALID_SOCKET(sock)) {
        result.error = NTP_ERR_SOCKET_CREATE;
        goto cleanup;
    }

#ifdef _WIN32
    DWORD timeout = NTP_TIMEOUT_SEC * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv_timeout = {NTP_TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));
#endif

    /* 构造标准 NTP 客户端请求包 */
    packet.li_vn_mode = 0x1B; /* LI=0, VN=3, Mode=3(客户端) */
    
    /* 记录发送时间（T1） */
    double t1 = get_local_time_double();
    uint32_t t1_sec = (uint32_t)t1 + NTP_TIMESTAMP_DELTA;
    uint32_t t1_frac = (uint32_t)((t1 - (uint32_t)t1) * 4294967296.0);
    
    /* 设置发送时间戳字段（网络字节序） */
    packet.trans_ts_sec = htonl(t1_sec);
    packet.trans_ts_frac = htonl(t1_frac);

    if (sendto(sock, (char*)&packet, sizeof(packet), 0, res->ai_addr, (int)res->ai_addrlen) < 0) {
        result.error = NTP_ERR_SEND_FAILED;
        goto cleanup;
    }

    /* 接收响应 */
    int bytes = recv(sock, (char*)&packet, sizeof(packet), 0);
    double t4 = get_local_time_double();

    if (bytes < NTP_PACKET_SIZE) {
        result.error = NTP_ERR_RECV_TIMEOUT;
        goto cleanup;
    }

    /* 验证响应合法性 */
    if (!validate_ntp_response(&packet, t1_sec, t1_frac)) {
        result.error = NTP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }

    /* 提取时间戳 */
    uint32_t t2_sec = ntohl(packet.recv_ts_sec);
    uint32_t t2_fra = ntohl(packet.recv_ts_frac);
    uint32_t t3_sec = ntohl(packet.trans_ts_sec);
    uint32_t t3_fra = ntohl(packet.trans_ts_frac);

    double t2 = (double)(t2_sec - NTP_TIMESTAMP_DELTA) + (double)t2_fra / 4294967296.0;
    double t3 = (double)(t3_sec - NTP_TIMESTAMP_DELTA) + (double)t3_fra / 4294967296.0;

    /* NTP 算法: 
     * delay = (T4-T1) - (T3-T2)
     * offset = ((T2-T1) + (T3-T4)) / 2
     * corrected_time = T3 + delay/2
     */
    result.delay = (t4 - t1) - (t3 - t2);
    result.corrected_time = t3 + (result.delay / 2.0);
    result.error = NTP_SUCCESS;

cleanup:
    if (!IS_INVALID_SOCKET(sock)) CLOSE_SOCKET(sock);
    if (res) freeaddrinfo(res);
    return result;
}

/* --- 多次采样求平均 --- */
ntp_result sync_with_server_multi_sample(const char* hostname, int samples) {
    ntp_result results[MAX_SAMPLES];
    int success_count = 0;
    double sum_time = 0.0;
    double sum_delay = 0.0;
    ntp_result final = {0.0, 0.0, NTP_ERR_RECV_TIMEOUT};

    printf("正在同步 %s (%d次采样)...\n", hostname, samples);

    for (int i = 0; i < samples; i++) {
        results[i] = query_ntp_server(hostname);
        if (results[i].error == NTP_SUCCESS) {
            sum_time += results[i].corrected_time;
            sum_delay += results[i].delay;
            success_count++;
            printf("  采样 %d/%d: 延迟 %.2f ms ✓\n", i+1, samples, results[i].delay * 1000.0);
        } else {
            printf("  采样 %d/%d: %s ✗\n", i+1, samples, ntp_error_strings[results[i].error]);
        }
    }

    if (success_count == 0) {
        printf("[失败] 所有采样均失败\n\n");
        return final;
    }

    /* 计算平均值 */
    final.corrected_time = sum_time / success_count;
    final.delay = sum_delay / success_count;
    final.error = NTP_SUCCESS;

    printf("[成功] 平均延迟: %.2f ms | 成功率: %d/%d\n", 
           final.delay * 1000.0, success_count, samples);

    return final;
}

/* --- 使用说明 --- */
void print_usage(const char* prog_name) {
    printf("用法: %s [选项] [NTP服务器]\n\n", prog_name);
    printf("选项:\n");
    printf("  -s <次数>  多次采样求平均（1-5次，默认1次）\n");
    printf("  -h         显示此帮助信息\n\n");
    printf("示例:\n");
    printf("  %s                          # 使用内置服务器池\n", prog_name);
    printf("  %s time.google.com          # 指定服务器\n", prog_name);
    printf("  %s -s 3 ntp.aliyun.com      # 3次采样求平均\n\n", prog_name);
    printf("注意:\n");
#ifdef _WIN32
    printf("  Windows: 请以管理员身份运行\n");
#else
    printf("  Linux: 请使用 sudo 运行\n");
#endif
}

int main(int argc, char* argv[]) {
    int samples = 1;
    char* custom_server = NULL;

    /* 解析命令行参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) {
                samples = atoi(argv[++i]);
                if (samples < 1 || samples > MAX_SAMPLES) {
                    fprintf(stderr, "[错误] 采样次数必须在 1-%d 之间\n", MAX_SAMPLES);
                    return 1;
                }
            } else {
                fprintf(stderr, "[错误] -s 参数需要指定采样次数\n");
                return 1;
            }
        } else if (argv[i][0] != '-') {
            custom_server = argv[i];
        }
    }

    if (!init_networking()) return 1;

    int success = 0;
    ntp_result result;

    /* 阶段1: 尝试用户指定服务器 */
    if (custom_server) {
        if (!validate_hostname(custom_server)) {
            fprintf(stderr, "[错误] 无效的主机名: %s\n", custom_server);
            cleanup_networking();
            return 1;
        }

        printf("=== 阶段 1: 用户指定服务器 ===\n");
        result = sync_with_server_multi_sample(custom_server, samples);
        
        if (result.error == NTP_SUCCESS) {
            ntp_error_t set_error = set_system_time_platform(result.corrected_time);
            if (set_error == NTP_SUCCESS) {
                time_t final_sec = (time_t)result.corrected_time;
                printf("✓ 系统时间已更新: %s\n", ctime(&final_sec));
                success = 1;
            } else {
                fprintf(stderr, "[错误] %s\n", ntp_error_strings[set_error]);
#ifdef _WIN32
                fprintf(stderr, "提示: 请以管理员身份运行命令提示符\n");
#else
                fprintf(stderr, "提示: 请使用 sudo 运行此程序\n");
#endif
            }
        } else {
            printf("[提示] 准备切换至内置备用服务器...\n\n");
        }
    }

    /* 阶段2: 轮询内置服务器 */
    if (!success) {
        printf("=== 阶段 2: 内置备用服务器池 ===\n");
        for (int i = 0; i < INTERNAL_SERVER_COUNT; i++) {
            result = sync_with_server_multi_sample(INTERNAL_NTP_SERVERS[i], samples);
            
            if (result.error == NTP_SUCCESS) {
                ntp_error_t set_error = set_system_time_platform(result.corrected_time);
                if (set_error == NTP_SUCCESS) {
                    time_t final_sec = (time_t)result.corrected_time;
                    printf("✓ 系统时间已更新: %s\n", ctime(&final_sec));
                    success = 1;
                    break;
                } else {
                    fprintf(stderr, "[错误] %s\n", ntp_error_strings[set_error]);
                }
            }
        }
    }

    if (!success) {
        fprintf(stderr, "\n[严重错误] 所有NTP服务器均同步失败\n");
        fprintf(stderr, "请检查:\n");
        fprintf(stderr, "  1. 网络连接是否正常\n");
        fprintf(stderr, "  2. 防火墙是否阻止 UDP 123 端口\n");
        fprintf(stderr, "  3. 是否有足够权限修改系统时间\n");
    }

    cleanup_networking();
    return success ? 0 : 1;
}
