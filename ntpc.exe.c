#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define NTP_PORT 123
#define NTP_PACKET_SIZE 48
#define NTP_TIMESTAMP_DELTA 2208988800ull // 1900-1970时间差(秒)
#define WINDOWS_TICK 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL // 1601-1970时间差(秒)

// 使用紧凑结构体避免对齐问题
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

void print_error(const char *msg) {
    fprintf(stderr, "错误: %s (代码: %d)\n", msg, WSAGetLastError());
}

// 精确的时间转换函数
void ntp_time_to_system_time(uint32_t ntp_sec, uint32_t ntp_frac, SYSTEMTIME *st) {
    // 转换字节序
    uint32_t sec = ntohl(ntp_sec);
    uint32_t frac = ntohl(ntp_frac);

    // 转换为Unix时间戳(1970基准)
    time_t unix_time = sec - NTP_TIMESTAMP_DELTA;

    // 转换为Windows FILETIME(1601基准)
    ULONGLONG win_time = ((ULONGLONG)unix_time + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK;

    // 精确添加小数部分(使用整数运算避免浮点误差)
    win_time += (ULONGLONG)frac * 10000000ULL / 0x100000000ULL;

    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(win_time & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(win_time >> 32);

    // 转换为UTC系统时间
    FileTimeToSystemTime(&ft, st);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s pool.ntp.org\n", argv[0]);
        fprintf(stderr, "      %s ntp.aliyun.com\n", argv[0]);
        return 1;
    }

    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server_addr;
    ntp_packet packet = {0};
    char buffer[NTP_PACKET_SIZE];
    int bytes_received;

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        print_error("Winsock初始化失败");
        return 1;
    }

    // 创建UDP套接字
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == INVALID_SOCKET) {
        print_error("套接字创建失败");
        WSACleanup();
        return 1;
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(NTP_PORT);

    // 解析服务器地址
    struct hostent *host = gethostbyname(argv[1]);
    if (!host) {
        print_error("无法解析主机名");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);

    // 设置更长的超时(5秒)
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    // 构建NTP请求包
    packet.li_vn_mode = 0x1B; // LI=0, VN=3, Mode=3

    // 发送请求
    if (sendto(sock, (char*)&packet, sizeof(packet), 0,
              (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        print_error("发送请求失败");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 接收响应
    bytes_received = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes_received < sizeof(ntp_packet)) {
        print_error("接收响应失败或数据不完整");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // 关闭套接字
    closesocket(sock);
    WSACleanup();

    // 直接解析缓冲区数据（避免结构体对齐问题）
    uint32_t trans_ts_sec = *(uint32_t*)(buffer + 40);
    uint32_t trans_ts_frac = *(uint32_t*)(buffer + 44);

    // 转换NTP时间为系统时间
    SYSTEMTIME utc_time;
    ntp_time_to_system_time(trans_ts_sec, trans_ts_frac, &utc_time);

    // 设置系统时间(需要管理员权限)
    if (!SetSystemTime(&utc_time)) {
        fprintf(stderr, "设置系统时间失败 (错误: %lu)\n", GetLastError());
        fprintf(stderr, "请以管理员权限运行此程序\n");
        return 1;
    }

    // 获取并显示本地时间
    SYSTEMTIME local_time;
    GetLocalTime(&local_time);

    char local_buf[64], utc_buf[64];
    sprintf(local_buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            local_time.wYear, local_time.wMonth, local_time.wDay,
            local_time.wHour, local_time.wMinute, local_time.wSecond, local_time.wMilliseconds);

    sprintf(utc_buf, "%04d-%02d-%02d %02d:%02d:%02d",
            utc_time.wYear, utc_time.wMonth, utc_time.wDay,
            utc_time.wHour, utc_time.wMinute, utc_time.wSecond);

    printf("系统时间已更新!\n");
    printf("本地时间: %s\n", local_buf);
    printf("UTC 时间: %s\n", utc_buf);

    return 0;
}
