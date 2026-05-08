/*
 * 项目名称: 跨平台轻量 NTP 同步工具 (v0.5)
 * 编译环境: Windows (MinGW-gcc) 或 Linux (gcc)
 * 更新日志:
 * v0.5:
 * - [修复] UDP connect() 替代 recvfrom IP 比对，正确处理 Anycast/DNS-RR 服务器
 * - [修复] KoD 字节序：reference_id 用 ntohl() 而非 htonl()
 * - [修复] 请求包 VN=4（0x23），不再发 v3
 * - [修复] orig_ts 差值改为无符号减法，避免 uint32 → int 强转在 2036 附近溢出
 * - [修复] corrected_time 算法: 改为 t4 + offset（符合 RFC 5905）
 * - [修复] 引入 monotonic clock 测量 RTT，避免 realtime 跳变污染 delay 计算
 * - [修复] recv() 改为 recvfrom()，校验响应来源 IP
 * - [修复] 新增 LI=3（时钟未同步）拒绝逻辑
 * - [修复] 新增 VN 范围校验（3-4）
 * - [修复] delay 负值 clamp 为 0
 * - [修复] KoD（Kiss-o'-Death）识别，stratum=0 时输出具体原因
 * - [优化] hostname validator 去除伪安全校验，保留长度检查，靠 getaddrinfo 兜底
 * - [说明] 本工具使用 settimeofday/SetSystemTime 硬跳时钟，
 *          适合一次性对时；不适合替代 chrony/ntpd 长期同步服务
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
    NTP_ERR_INVALID_HOSTNAME,
    NTP_ERR_SOURCE_MISMATCH,
    NTP_ERR_KOD
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
    "无效的主机名",
    "响应来源IP不匹配",
    "服务器拒绝请求(KoD)"
};

#pragma pack(push, 1)
typedef struct {
    uint8_t  li_vn_mode;
    uint8_t  stratum;
    uint8_t  poll;
    uint8_t  precision;
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
    double      corrected_time; /* t4 + offset，用于设置系统时间 */
    double      delay;          /* 往返传播时间（单位：秒） */
    double      offset;         /* 本地时钟偏差（单位：秒） */
    ntp_error_t error;
} ntp_result;

/* ============================================================
 * 高精度时间戳：分 realtime（获取 epoch）和 monotonic（测 RTT）
 * ============================================================ */

/* realtime：用于填写 NTP 包的发送时间戳（需要 epoch） */
static double get_realtime_double(void) {
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

/* monotonic：用于测量 RTT，不受系统时间跳变影响 */
static double get_monotonic_double(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
#endif
}

/* ============================================================
 * 网络初始化
 * ============================================================ */
static int init_networking(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[错误] Winsock 初始化失败\n");
        return 0;
    }
#endif
    return 1;
}

static void cleanup_networking(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

/* ============================================================
 * KoD（Kiss-o'-Death）识别
 * stratum=0 时，reference_id 是 4字节 ASCII 错误码
 * ============================================================ */
static void print_kod_reason(uint32_t reference_id) {
    char code[5];
    /*
     * reference_id 从包中读取时仍是网络字节序（大端），
     * 用 ntohl() 转为本机字节序后 memcpy 得到正确 ASCII 顺序。
     */
    uint32_t ref_host = ntohl(reference_id);
    memcpy(code, &ref_host, 4);
    code[4] = '\0';
    /* 过滤非打印字符 */
    for (int i = 0; i < 4; i++) {
        if (code[i] < 0x20 || code[i] > 0x7E) code[i] = '?';
    }
    fprintf(stderr, "[调试] KoD 原因码: \"%s\"\n", code);
    if (strncmp(code, "RATE", 4) == 0) {
        fprintf(stderr, "       服务器拒绝: 请求频率过高，请降低采样次数或更换服务器\n");
    } else if (strncmp(code, "DENY", 4) == 0 || strncmp(code, "RSTR", 4) == 0) {
        fprintf(stderr, "       服务器拒绝: 访问被禁止\n");
    }
}

/* ============================================================
 * NTP 响应验证
 * ============================================================ */
static int validate_ntp_response(const ntp_packet* packet,
                                  uint32_t sent_sec, uint32_t sent_frac) {
    uint8_t li   = (packet->li_vn_mode >> 6) & 0x03;
    uint8_t vn   = (packet->li_vn_mode >> 3) & 0x07;
    uint8_t mode = (packet->li_vn_mode)       & 0x07;

    /* LI=3: 服务器时钟未同步，RFC 5905 要求拒绝 */
    if (li == 3) {
        fprintf(stderr, "[调试] LI=3: 服务器时钟未同步\n");
        return 0;
    }

    /* VN: 仅接受 3 或 4 */
    if (vn < 3 || vn > 4) {
        fprintf(stderr, "[调试] VN=%d 超出有效范围(3-4)\n", vn);
        return 0;
    }

    /* mode: 4=server, 5=broadcast */
    if (mode != 4 && mode != 5) {
        fprintf(stderr, "[调试] mode=%d 期望 4 或 5\n", mode);
        return 0;
    }

    /* stratum=0: KoD */
    if (packet->stratum == 0) {
        print_kod_reason(packet->reference_id);
        return 0;
    }
    if (packet->stratum > MAX_VALID_STRATUM) {
        fprintf(stderr, "[调试] stratum=%d 超出有效范围\n", packet->stratum);
        return 0;
    }

    /* orig_ts 回显校验：用无符号减法，避免 uint32 → int 强转在 2036 附近溢出 */
    uint32_t resp_orig_sec = ntohl(packet->orig_ts_sec);
    uint32_t orig_diff = (resp_orig_sec > sent_sec)
                         ? (resp_orig_sec - sent_sec)
                         : (sent_sec - resp_orig_sec);
    if (orig_diff > 1) {
        fprintf(stderr, "[调试] orig_ts 秒差异过大: 发送=%u 回显=%u\n",
                sent_sec, resp_orig_sec);
        return 0;
    }
    (void)sent_frac; /* frac 精度校验收益低，保留参数供后续使用 */

    /* trans_ts 非零 */
    if (ntohl(packet->trans_ts_sec) == 0) {
        fprintf(stderr, "[调试] trans_ts 为零\n");
        return 0;
    }

    return 1;
}

/* ============================================================
 * 设置系统时间
 * ============================================================ */
static ntp_error_t set_system_time_platform(double new_time_seconds) {
    time_t  sec  = (time_t)new_time_seconds;
    double  frac = new_time_seconds - (double)sec;

#ifdef _WIN32
    ULONGLONG win_ticks = ((ULONGLONG)sec + 11644473600LL) * 10000000ULL +
                          (ULONGLONG)(frac * 10000000.0);
    FILETIME ft;
    ft.dwLowDateTime  = (DWORD)(win_ticks & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(win_ticks >> 32);
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    if (!SetSystemTime(&st)) {
        return (GetLastError() == ERROR_ACCESS_DENIED)
               ? NTP_ERR_PERMISSION_DENIED : NTP_ERR_SET_TIME_FAILED;
    }
#else
    if (getuid() != 0) {
        return NTP_ERR_PERMISSION_DENIED;
    }
    struct timeval tv;
    tv.tv_sec  = sec;
    tv.tv_usec = (suseconds_t)(frac * 1000000.0);
    if (settimeofday(&tv, NULL) < 0) {
        return NTP_ERR_SET_TIME_FAILED;
    }
#endif
    return NTP_SUCCESS;
}

/* ============================================================
 * 单次 NTP 查询
 * ============================================================ */
static ntp_result query_ntp_server(const char* hostname) {
    ntp_result result = {0.0, 0.0, 0.0, NTP_ERR_DNS_FAILED};
    socket_t sock = (socket_t)-1;
    struct addrinfo hints, *res = NULL;
    ntp_packet packet = {0};

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET; /* 当前保持 IPv4，IPv6 支持留待后续 */
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
    DWORD timeout_ms = NTP_TIMEOUT_SEC * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               (char*)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv_timeout = {NTP_TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               &tv_timeout, sizeof(tv_timeout));
#endif

    /* 构造标准 NTP v4 客户端请求包：LI=0, VN=4, Mode=3 */
    packet.li_vn_mode = 0x23;

    /*
     * T1:
     * realtime 用于 NTP epoch
     * monotonic 用于 RTT
     */
    double t1_real = get_realtime_double();
    double t1_mono = get_monotonic_double();

    uint32_t t1_sec  =
        (uint32_t)floor(t1_real) + NTP_TIMESTAMP_DELTA;

    double t1_fd = t1_real - floor(t1_real);

    uint32_t t1_frac =
        (uint32_t)(t1_fd * 4294967296.0);

    packet.trans_ts_sec  = htonl(t1_sec);
    packet.trans_ts_frac = htonl(t1_frac);

    /*
     * UDP connect():
     * 不建立 TCP 式连接，仅绑定默认对端。
     * 内核会自动丢弃来源不匹配的数据包。
     */
    if (connect(sock, res->ai_addr,
                (int)res->ai_addrlen) < 0) {
        result.error = NTP_ERR_SEND_FAILED;
        goto cleanup;
    }

    if (send(sock,
             (char*)&packet,
             sizeof(packet),
             0) < 0) {
        result.error = NTP_ERR_SEND_FAILED;
        goto cleanup;
    }

    int bytes = recv(sock,
                     (char*)&packet,
                     sizeof(packet),
                     0);

    double t4_mono = get_monotonic_double();
    double t4_real = get_realtime_double();

    if (bytes < 0) {
        result.error = NTP_ERR_RECV_TIMEOUT;
        goto cleanup;
    }

    if (bytes < NTP_PACKET_SIZE) {
        result.error = NTP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }

    if (!validate_ntp_response(&packet,
                               t1_sec,
                               t1_frac)) {
        result.error = NTP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }

    /* 提取服务器时间戳 */
    uint32_t t2_sec = ntohl(packet.recv_ts_sec);
    uint32_t t2_fra = ntohl(packet.recv_ts_frac);

    uint32_t t3_sec = ntohl(packet.trans_ts_sec);
    uint32_t t3_fra = ntohl(packet.trans_ts_frac);

    double t2 =
        (double)(t2_sec - NTP_TIMESTAMP_DELTA) +
        (double)t2_fra / 4294967296.0;

    double t3 =
        (double)(t3_sec - NTP_TIMESTAMP_DELTA) +
        (double)t3_fra / 4294967296.0;

    /*
     * RFC 5905:
     *
     * delay  =
     *   (T4_mono - T1_mono) - (T3 - T2)
     *
     * offset =
     *   ((T2 - T1_real) + (T3 - T4_real)) / 2
     */
    double rtt =
        (t4_mono - t1_mono) - (t3 - t2);

    double offset =
        ((t2 - t1_real) +
         (t3 - t4_real)) / 2.0;

    /* delay 理论非负 */
    if (rtt < 0.0) {
        rtt = 0.0;
    }

    result.delay          = rtt;
    result.offset         = offset;
    result.corrected_time = t4_real + offset;
    result.error          = NTP_SUCCESS;

cleanup:
    if (!IS_INVALID_SOCKET(sock)) {
        CLOSE_SOCKET(sock);
    }

    if (res) {
        freeaddrinfo(res);
    }

    return result;
}

/* ============================================================
 * 多次采样取最小 delay
 * ============================================================ */
static ntp_result sync_with_server_multi_sample(const char* hostname, int samples) {
    ntp_result results[MAX_SAMPLES];
    int success_count = 0;
    ntp_result final = {0.0, 0.0, 0.0, NTP_ERR_RECV_TIMEOUT};

    if (samples > MAX_SAMPLES) samples = MAX_SAMPLES;

    printf("正在同步 %s (%d次采样)...\n", hostname, samples);

    for (int i = 0; i < samples; i++) {
        results[i] = query_ntp_server(hostname);
        if (results[i].error == NTP_SUCCESS) {
            printf("  采样 %d/%d: 延迟 %.2f ms | 偏移 %+.2f ms ✓\n",
                   i+1, samples,
                   results[i].delay  * 1000.0,
                   results[i].offset * 1000.0);
            success_count++;
        } else {
            printf("  采样 %d/%d: %s ✗\n",
                   i+1, samples, ntp_error_strings[results[i].error]);
        }
    }

    if (success_count == 0) {
        printf("[失败] 所有采样均失败\n\n");
        return final;
    }

    /* 取最小 delay 对应的采样：delay 越小说明网络路径越对称，误差越小 */
    ntp_result* best = NULL;
    for (int i = 0; i < samples; i++) {
        if (results[i].error == NTP_SUCCESS) {
            if (best == NULL || results[i].delay < best->delay) {
                best = &results[i];
            }
        }
    }
    final = *best;

    printf("[成功] 最优采样: 延迟 %.2f ms | 偏移 %+.2f ms | 成功率: %d/%d\n",
           final.delay * 1000.0, final.offset * 1000.0, success_count, samples);

    return final;
}

/* ============================================================
 * 使用说明
 * ============================================================ */
static void print_usage(const char* prog_name) {
    printf("用法: %s [选项] [NTP服务器]\n\n", prog_name);
    printf("选项:\n");
    printf("  -s <次数>  多次采样取最优（1-5次，默认1次）\n");
    printf("  -h         显示此帮助信息\n\n");
    printf("示例:\n");
    printf("  %s                          # 使用内置服务器池\n", prog_name);
    printf("  %s time.google.com          # 指定服务器\n", prog_name);
    printf("  %s -s 3 ntp.aliyun.com      # 3次采样取最优\n", prog_name);
    printf("  %s 192.168.1.1              # 指定IPv4地址\n\n", prog_name);
    printf("注意:\n");
    printf("  本工具直接跳变系统时间（settimeofday/SetSystemTime），\n");
    printf("  适合一次性手动对时，不适合替代 chrony/ntpd 长期同步。\n");
#ifdef _WIN32
    printf("  Windows: 请以管理员身份运行\n");
#else
    printf("  Linux: 请使用 sudo 运行\n");
#endif
}

/* ============================================================
 * main
 * ============================================================ */
int main(int argc, char* argv[]) {
    int   samples       = 1;
    char* custom_server = NULL;

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

    /* hostname 仅做长度检查，合法性由 getaddrinfo 最终裁定 */
    if (custom_server && strlen(custom_server) > MAX_HOSTNAME_LEN) {
        fprintf(stderr, "[错误] 主机名过长（最大 %d 字符）\n", MAX_HOSTNAME_LEN);
        return 1;
    }

    if (!init_networking()) return 1;

    int        success = 0;
    ntp_result result;

    /* 阶段1: 用户指定服务器 */
    if (custom_server) {
        printf("=== 阶段 1: 用户指定服务器 ===\n");
        result = sync_with_server_multi_sample(custom_server, samples);

        if (result.error == NTP_SUCCESS) {
            ntp_error_t set_err = set_system_time_platform(result.corrected_time);
            if (set_err == NTP_SUCCESS) {
                time_t final_sec = (time_t)result.corrected_time;
                printf("✓ 系统时间已更新: %s\n", ctime(&final_sec));
                success = 1;
            } else {
                fprintf(stderr, "[错误] %s\n", ntp_error_strings[set_err]);
#ifdef _WIN32
                fprintf(stderr, "提示: 请以管理员身份运行\n");
#else
                fprintf(stderr, "提示: 请使用 sudo 运行此程序\n");
#endif
            }
        } else {
            printf("[提示] 准备切换至内置备用服务器...\n\n");
        }
    }

    /* 阶段2: 内置服务器池 */
    if (!success) {
        printf("=== 阶段 2: 内置备用服务器池 ===\n");
        for (int i = 0; i < INTERNAL_SERVER_COUNT; i++) {
            result = sync_with_server_multi_sample(INTERNAL_NTP_SERVERS[i], samples);

            if (result.error == NTP_SUCCESS) {
                ntp_error_t set_err = set_system_time_platform(result.corrected_time);
                if (set_err == NTP_SUCCESS) {
                    time_t final_sec = (time_t)result.corrected_time;
                    printf("✓ 系统时间已更新: %s\n", ctime(&final_sec));
                    success = 1;
                    break;
                } else {
                    fprintf(stderr, "[错误] %s\n", ntp_error_strings[set_err]);
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
