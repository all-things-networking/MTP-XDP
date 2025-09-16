#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <assert.h>
#include <mutex>
#include <ctime>

#include <iostream>
#include <thread>
#include <list>
#include <string>
#include <unordered_map>
#include <atomic>

#include "../lib/include/mtp_only.h"

#define MAX_THREADS 16

#define DATA_BLOCK_SIZE 65536
#define SHORT_RESPONSE_SIZE 100
#define TIMESTAMP_BYTES 1000

unsigned int max_buf_size = 4096;
int wait_seconds = 0;
bool multiport = false;
bool dump_io_stats = false;
bool short_response = true;
unsigned int max_outstanding = 1;
unsigned int nr_flows = 1;
unsigned int nr_threads = 1;
unsigned int nr_queues = 1;
// TODO: change it back to 8000 later
unsigned int message_bytes_short = 100000; //8000;
unsigned int message_bytes_long = 1000000;
unsigned int message_bytes = 100;
std::string server_ip_str = "192.168.6.2";
uint16_t server_port = 50000;

std::list<std::thread> threads;
std::mutex conn_fds_mtx;
std::list<int> conn_fds;

std::mutex mtx;
static unsigned int ready_threads = 0;

uint64_t total_out = 0;
uint64_t total_in = 0;
static std::atomic<uint64_t> total_req_bytes[MAX_THREADS] = {};
uint64_t prev_total_req_bytes[MAX_THREADS] = {};
static std::atomic<uint64_t> total_resp_bytes[MAX_THREADS] = {};
uint64_t prev_total_resp_bytes[MAX_THREADS] = {};
static std::atomic<uint32_t> avg_nr_events(0);


struct connection {
    int fd;
    unsigned int recv_len;
    unsigned int pending_bytes1;
    unsigned int pending_bytes2;
    unsigned int total_bytes1;
    unsigned int total_bytes2;
    unsigned int message_bytes1;
    unsigned int message_bytes2;

    unsigned int arrival_count;

    unsigned int waiting_to_transfer_bytes;
    unsigned int arrival_bytes;
    //unsigned int message_bytes;
    struct app_event event;
    unsigned int max_outstanding;
    char *buf1;
    char *buf2;
    bool no_epoll_out;
    unsigned short curr_buffer_send;
    unsigned short curr_buffer_receive;

    float start_time;
    float end_time;
    
    connection(int fd, unsigned int message_bytes_long, unsigned int message_bytes_short, unsigned int max_outstanding) : fd(fd), /*message_bytes(message_bytes), */max_outstanding(max_outstanding) {
        no_epoll_out = false;
        recv_len = 0;
        //event.data_size = message_bytes;
        message_bytes1 = message_bytes_short;
        message_bytes2 = message_bytes_long;
        total_bytes1 = message_bytes_short * max_outstanding;
        total_bytes2 = message_bytes_long * max_outstanding;
        pending_bytes1 = total_bytes1;
        pending_bytes2 = total_bytes2;
        buf1 = (char *)calloc(1, total_bytes1);
        buf2 = (char *)calloc(1, total_bytes2);
        curr_buffer_send = 1;
        curr_buffer_receive = 1;
        arrival_count = 0;
        waiting_to_transfer_bytes = message_bytes_short;
    }
};

static inline int connection_send(unsigned int tid, struct connection *c)
{
    ssize_t ret;
    uint32_t target_bytes;
    uint32_t write_bytes_with_stream_id;
    int need_epoll_out = 0;
    /*if(c->pending_bytes1 == c->total_bytes1){
        c->start_time = time(NULL);
    }*/

    printf("START SEND\n");
    // Transmit messages as much as possible through this connection until we reach max_outstanding or no buffer space
    while (c->pending_bytes1/* || c->pending_bytes2*/) {
        /*if(c->curr_buffer_send == 1){
            target_bytes = std::min(c->pending_bytes1, c->message_bytes1);
            ret = write(c->fd, c->buf1 + (c->total_bytes1 - c->pending_bytes1), std::min(target_bytes, (unsigned int)DATA_BLOCK_SIZE));
        }else{
            target_bytes = std::min(c->pending_bytes2, c->message_bytes2);
            ret = write(c->fd, c->buf2 + (c->total_bytes2 - c->pending_bytes2), std::min(target_bytes, (unsigned int)DATA_BLOCK_SIZE));
        }*/
        target_bytes = std::min(c->pending_bytes1, c->message_bytes1);
        write_bytes_with_stream_id = std::min(target_bytes, (unsigned int)DATA_BLOCK_SIZE);
        write_bytes_with_stream_id |= 1u << 31;

        ret = write(c->fd, c->buf1 + (c->total_bytes1 - c->pending_bytes1), write_bytes_with_stream_id);

        printf("SEND %lu %u\n", ret, c->pending_bytes1);

        if (ret > 0) {
            /*if(c->curr_buffer_send == 1){
                c->pending_bytes1 -= ret;
                c->waiting_to_transfer_bytes -= ret;
                if(c->waiting_to_transfer_bytes <=0){
                    c->waiting_to_transfer_bytes += c->message_bytes2;//switch to long message
                    c->curr_buffer_send = 2;
                }
            }else{
                c->pending_bytes2 -= ret;
                c->waiting_to_transfer_bytes -= ret;
                if(c->waiting_to_transfer_bytes <=0){
                    c->waiting_to_transfer_bytes += c->message_bytes1;//switch to short message
                    c->curr_buffer_send = 1;
                }
            }*/
            c->pending_bytes1 -= ret;

            total_req_bytes[tid].fetch_add(ret);
        }
        else {
            // no buffer space
            need_epoll_out = 1;
            break;
        }
    }
    printf("END SEND\n\n");
    return need_epoll_out;
}

static inline void connection_recv(unsigned int tid, struct connection *c, uint32_t stream_id)
{
    ssize_t ret;
    bool wait_response = c->pending_bytes1 + c->message_bytes1 <= c->total_bytes1;

    uint32_t target_bytes_with_stream_id;

    printf("START RECV\n");

    // Receive messages as much as possible through this connection if there are outstanding messages
    while (wait_response) {
        uint32_t target_bytes = short_response ? SHORT_RESPONSE_SIZE : c->message_bytes1;

        target_bytes_with_stream_id = target_bytes;
        if(stream_id & 1u << 0) {
            //printf("STREAM 0\n");
            target_bytes_with_stream_id = target_bytes | 1u << 31;
        }
        if(stream_id & 1u << 1) {
            //printf("STREAM 1\n");
            target_bytes_with_stream_id = target_bytes_with_stream_id | 1u << 30;
        }
        //target_bytes_with_stream_id = target_bytes | 1u << 31;

        ret = read(c->fd, c->buf1 + c->recv_len, target_bytes_with_stream_id);

        printf("RECEIVED %lu %u %u\n", ret, c->pending_bytes1, c->recv_len);
        if (ret > 0) {
            c->recv_len += ret;
            total_resp_bytes[tid].fetch_add(ret);
        } else {
            // no more data
            break;
        }
        if (c->recv_len >= target_bytes) {
            c->recv_len -= target_bytes;
            c->pending_bytes1 += c->message_bytes1;
        }
    }
    printf("END RECV\n\n");
}

static inline int connection_events(unsigned int tid, struct connection *c, uint32_t events, uint32_t stream_id)
{   
    if (events & EPOLLIN) {
        connection_recv(tid, c, stream_id);
    }

    return connection_send(tid, c);
}

void thread_func(unsigned int tid)
{
    struct connection *c;
    int epfd;
    struct epoll_event ev, events[256];
    struct in_addr server_ip_addr;
    uint16_t t_server_port;
    if (multiport)
        t_server_port = server_port + tid;
    else
        t_server_port = server_port;
    unsigned int t_nr_flows = nr_flows / nr_threads;
    if (t_nr_flows == 0) {
        t_nr_flows = 1;
    }
    
    assert(inet_pton(AF_INET, server_ip_str.c_str(), &server_ip_addr) == 1);

    while (1) {
        mtx.lock();
        if (tid == ready_threads) {
            mtx.unlock();
            break;
        }
        mtx.unlock();
    }

    epfd = epoll_create1(0);

    if (epfd < 0) {
        fprintf(stderr, "Failed to create epoll\n");
        return;
    }

    for (unsigned int i = 0; i < t_nr_flows; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            fprintf(stderr, "Failed to create socket\n");
            perror("\n");
            return;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(t_server_port);
        server_addr.sin_addr.s_addr = server_ip_addr.s_addr;
        if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            fprintf(stderr, "Failed to connect to server\n");
            perror("connect");
            close(fd);
            return;
        }

        // close(fd);

        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
            fprintf(stderr, "Failed to set non-blocking\n");
            close(fd);
            return;
        }

        ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
        ev.data.ptr = new connection(fd, message_bytes_long, message_bytes_short, max_outstanding);

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            fprintf(stderr, "Failed to add fd to epoll\n");
            close(fd);
            close(epfd);
            return;
        }
        conn_fds_mtx.lock();
        conn_fds.push_back(fd);
        conn_fds_mtx.unlock();
    }

    printf("Connected to %s:%d successfully, total connections (%u) on Thread#%u\n", server_ip_str.c_str(), t_server_port, t_nr_flows, tid);
    
    mtx.lock();
    ready_threads++;
    mtx.unlock();
    
    while (ready_threads < nr_threads) {
        usleep(1000);
    }

    sleep(wait_seconds);

    int stream_id = 0;
    while (1) {

        int nfds = epoll_wait(epfd, events, 128, -1);

        if (nfds) avg_nr_events.store((avg_nr_events.load() + nfds) / 2);
        for (int i = 0; i < nfds; i++) {
            stream_id = 0;
            if(events[i].events & 1u << 27) {
                //printf("STREAM ID 0");
                stream_id |= 1u << 0;
                events[i].events &= ~(1u << 27);
            }
            if(events[i].events & 1u << 26) {
                //printf("STREAM ID 1");
                stream_id |= 1u << 1;
                events[i].events &= ~(1u << 26);
            }

            c = (connection *)events[i].data.ptr;
            
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                fprintf(stderr, "EPOLLERR\n");
                conn_fds.remove(c->fd);
                // remove from epoll
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
                close(c->fd);
                continue;
            }

            int ret = connection_events(tid, c, events[i].events, stream_id);
            if (ret == 0 && !c->no_epoll_out) {
                ev.events = EPOLLIN | EPOLLERR;
                ev.data.ptr = c;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
                    fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                c->no_epoll_out = 1;
            } else if (ret == 1 && c->no_epoll_out) {
                ev.events = EPOLLIN | EPOLLERR | EPOLLOUT;
                ev.data.ptr = c;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
                    fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                c->no_epoll_out = 0;
            }
        }
    }

    close(epfd);
    for (auto &fd : conn_fds) {
        close(fd);
    }
}

int parse_args(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "t:q:f:b:i:p:so:mw:l:")) != -1) {
        switch (opt) {
            case 'b':
                message_bytes = std::stoi(optarg);
                break;
            case 'i':
                server_ip_str = optarg;
                break;
            case 'f':
                nr_flows = std::stoi(optarg);
                break;
            case 't':
                nr_threads = std::stoi(optarg);
                break;
            case 'l':
                max_buf_size = std::stoi(optarg);
                break;
            case 'q':
                nr_queues = std::stoi(optarg);
                break;
            case 'p':
                server_port = std::stoi(optarg);
                break;
            case 'w':
                wait_seconds = std::stoi(optarg);
                break;
            case 'd':
                dump_io_stats = true;
                break;
            case 's':
                short_response = false;
                break;
            case 'm':
                multiport = true;
                break;
            case 'o':
                max_outstanding = std::stoi(optarg);
                break;
            default:
                std::cout << "Usage: " << argv[0] << 
                    " [-t nr_threads, default:1]" <<
                    " [-l max_buf_size, default:4096]" << 
                    " [-q nr_queues, default:1]" <<
                    " [-b bytes, default:100]" << 
                    " [-i server_ip, default:192.168.6.2]" <<
                    " [-f nr_flows, default:1]"
                    " [-p server_port, default:50000]" << 
                    " [-w wait_seconds, default:0]" <<
                    " [-s enable short_response, default:true]" << 
                    " [-o max_outstanding, default:1]" <<
                    " [-m multiport, default:false]" << 
                    " [-d dump_io_stats]" << std::endl;
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (parse_args(argc, argv))
    {
        std::cout << "Failed to parse arguments." << std::endl;
        exit(EXIT_FAILURE);
    }

    for (unsigned int i = 0; i < nr_threads; i++) {
        threads.push_back(std::thread(thread_func, i));
    }

    std::thread([]() {
        while (1) {
            sleep(1);
            unsigned int _out = 0;
            unsigned int _in = 0;

            for (unsigned int i = 0; i < nr_threads; i++) {
                _out += total_req_bytes[i].load() - prev_total_req_bytes[i];
                _in += total_resp_bytes[i].load() - prev_total_resp_bytes[i];
                prev_total_req_bytes[i] = total_req_bytes[i].load();
                prev_total_resp_bytes[i] = total_resp_bytes[i].load();
            }
            total_out += _out;
            total_in += _in;

            printf("Throughput In/Out(%.2f/%.2f Gbps)(%.2f Kops) conn#(%lu), avg_nr_events(%u), total_out(%luB), total_in(%luB)\n", 
                _out * 8.0 / 1e9, _in * 8.0 / 1e9, _out / message_bytes_short / 1e3,
                conn_fds.size(), avg_nr_events.load(), total_out, total_in);
        }
    }).detach();

    for (auto &t : threads) {
        t.join();
    }

    return 0;
}