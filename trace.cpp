#include <iostream>
#include <cstdio>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <dlfcn.h>
#include <inttypes.h>
#include <sys/time.h>

const uint32_t COV_SERVER_PORT = 7155;

int covSenderFd{-1};
struct sockaddr_in covServer;

uint32_t stackDepth{0};

bool firstReport{true};
timeval firstReportTime;

void initSock()
{
    if (covSenderFd != -1)
    {
        return;
    }

    covSenderFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (covSenderFd < 0)
    {
        perror("Failed to create socket:");
        exit(44);
    }

    covServer.sin_family = AF_INET;
    covServer.sin_port = htons(COV_SERVER_PORT);
    covServer.sin_addr.s_addr = inet_addr("127.0.0.1");
}

void covSend(uint32_t depth, uint64_t current_time, void* pc, void* sp)
{
    initSock();

    uint64_t pc_int = reinterpret_cast<uint64_t>(pc);
    uint64_t sp_int = reinterpret_cast<uint64_t>(sp);

    uint8_t sendBuffer[4 + 8 + 8 + 8];
    std::memcpy(sendBuffer, &depth, 4);
    std::memcpy(sendBuffer + 4, &current_time, 8);
    std::memcpy(sendBuffer + 4 + 8, &pc_int, 8);
    std::memcpy(sendBuffer + 4 + 8 + 8, &sp_int, 8);

    if (sendto(covSenderFd, sendBuffer, sizeof(sendBuffer), 0, (struct sockaddr *)&covServer, sizeof(covServer)) < 0)
    {
        perror("Failed to sendto:");
        exit(45);
    }
}

uint64_t get_timestamp()
{
    if (firstReport)
    {
        firstReport = false;
        gettimeofday(&firstReportTime, 0);
        return 0;
    }

    timeval currentTime;
    gettimeofday(&currentTime, 0);
    return static_cast<uint64_t>(
        (currentTime.tv_sec - firstReportTime.tv_sec) * 1000000 + currentTime.tv_usec - firstReportTime.tv_usec
    );
}


extern "C" 
__attribute__((no_instrument_function))
void __cyg_profile_func_enter(void *this_fn,
                              void *call_site)
{
    stackDepth++;
    void* sp;
    __asm__("movq %%rsp, %0" : "=r"(sp));

    uint64_t current_time = get_timestamp();

    printf("[%u] T %" PRIu64 ", PC %p, SP %p\n", stackDepth, current_time, call_site, sp);

    covSend(stackDepth, current_time, call_site, sp);
}

extern "C" 
__attribute__((no_instrument_function))
void __cyg_profile_func_exit  (void *this_fn,
                               void *call_site)
{
    stackDepth--;
};
