/*
 * 项目名称: 跨平台高精度 NTP 同步工具 (v1.1)
 * 编译环境: Windows (MinGW-gcc) 或 Linux (gcc)
 * 更新日志:
 * - 保留 v1.0 所有 RTT 补偿与跨平台兼容代码
 * - [新增] 支持命令行参数指定自定义 NTP 服务器
 * - [新增] 自动回退机制：自定义失败后自动轮询内置服务器
 * * [编译命令]
 * Linux:   gcc ntp_sync.c -o ntp_sync
 * Windows: gcc ntp_sync.c -o ntp_sync.exe -lws2_32
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

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
#define NTP_TIMEOUT_SEC 3
#define NTP_TIMESTAMP_DELTA 2208988800ull

/* 内置 NTP 服务器池 */
const char* INTERNAL_NTP_SERVERS[] = {"ntp.aliyun.com", "pool.ntp.org"};
const int INTERNAL_SERVER_COUNT = 2;

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

/* --- 辅助函数：网络初始化 (保留自 v1.0) --- */
int init_networking() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#endif
    return 1;
}

void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* --- 辅助函数：高精度本地时间戳获取 (保留自 v1.0) --- */
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

/* --- 核心函数：设置系统时间并检测权限 (保留自 v1.0) --- */
int set_system_time_platform(double new_time_seconds) {
    time_t sec = (time_t)new_time_seconds;
    double frac = new_time_seconds - (double)sec;

#ifdef _WIN32
    SYSTEMTIME st;
    ULONGLONG win_ticks = ((ULONGLONG)sec + 11644473600LL) * 10000000ULL + (ULONGLONG)(frac * 10000000ULL);
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(win_ticks & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(win_ticks >> 32);
    FileTimeToSystemTime(&ft, &st);

    if (!SetSystemTime(&st)) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "[错误] 权限不足：请以管理员身份运行命令提示符。\n");
        }
        return 0;
    }
#else
    if (getuid() != 0) {
        fprintf(stderr, "[错误] 权限不足：请使用 sudo 运行此程序。\n");
        return 0;
    }
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = (suseconds_t)(frac * 1000000.0);
    if (settimeofday(&tv, NULL) < 0) return 0;
#endif
    return 1;
}

/* --- 核心逻辑：单次 NTP 会话 (保留 RTT 算法逻辑) --- */
int sync_with_server(const char* hostname) {
    socket_t sock;
    struct addrinfo hints, *res;
    ntp_packet packet = {0};

    printf("正在尝试同步: %s ... ", hostname);
    fflush(stdout);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(hostname, "123", &hints, &res) != 0) {
        printf("DNS 解析失败。\n");
        return 0;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (IS_INVALID_SOCKET(sock)) {
        freeaddrinfo(res);
        return 0;
    }

#ifdef _WIN32
    DWORD timeout = NTP_TIMEOUT_SEC * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv_timeout = {NTP_TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));
#endif

    packet.li_vn_mode = 0x1B;

    double t1 = get_local_time_double();
    if (sendto(sock, (char*)&packet, sizeof(packet), 0, res->ai_addr, (int)res->ai_addrlen) < 0) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return 0;
    }

    int bytes = recv(sock, (char*)&packet, sizeof(packet), 0);
    double t4 = get_local_time_double();

    if (bytes < NTP_PACKET_SIZE) {
        printf("响应超时。\n");
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return 0;
    }

    uint32_t t2_sec = ntohl(packet.recv_ts_sec);
    uint32_t t2_fra = ntohl(packet.recv_ts_frac);
    uint32_t t3_sec = ntohl(packet.trans_ts_sec);
    uint32_t t3_fra = ntohl(packet.trans_ts_frac);

    double t2 = (double)(t2_sec - NTP_TIMESTAMP_DELTA) + (double)t2_fra / 4294967296.0;
    double t3 = (double)(t3_sec - NTP_TIMESTAMP_DELTA) + (double)t3_fra / 4294967296.0;

    double delay = (t4 - t1) - (t3 - t2);
    double corrected_time = t3 + (delay / 2.0);

    if (set_system_time_platform(corrected_time)) {
        time_t final_sec = (time_t)corrected_time;
        printf("成功!\n[信息] 补偿延迟: %.3f ms | 当前时间: %s", delay * 1000.0, ctime(&final_sec));
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return 1;
    }

    CLOSE_SOCKET(sock);
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char* argv[]) {
    if (!init_networking()) return 1;

    int success = 0;

    /* 1. 优先尝试命令行参数指定的服务器 */
    if (argc > 1) {
        printf("=== 阶段 1: 尝试用户指定服务器 ===\n");
        if (sync_with_server(argv[1])) {
            success = 1;
        } else {
            printf("[提示] 用户指定的服务器失败，准备切换至内置备用服务器...\n\n");
        }
    }

    /* 2. 如果前一步失败或无参数，轮询内置服务器 */
    if (!success) {
        printf("=== 阶段 2: 轮询内置备用服务器 ===\n");
        for (int i = 0; i < INTERNAL_SERVER_COUNT; i++) {
            if (sync_with_server(INTERNAL_NTP_SERVERS[i])) {
                success = 1;
                break;
            }
        }
    }

    if (!success) {
        fprintf(stderr, "\n[严重错误] 所有可用 NTP 服务器均同步失败，请检查网络或防火墙 (UDP 123 端口)。\n");
    }

    cleanup_networking();
    return success ? 0 : 1;
}
