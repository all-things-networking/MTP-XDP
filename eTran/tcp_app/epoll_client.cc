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
unsigned int message_bytes_short = 8000; //8000;
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
    unsigned int recv_len1;
    unsigned int recv_len2;
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
    bool no_epoll_out1;
    bool no_epoll_out2;
    unsigned short curr_buffer_send;
    unsigned short curr_buffer_receive;

    float start_time;
    float end_time;
    
    connection(int fd, unsigned int message_bytes_short, unsigned int message_bytes_long, unsigned int max_outstanding) : fd(fd), /*message_bytes(message_bytes), */max_outstanding(max_outstanding) {
        no_epoll_out1 = false;
        no_epoll_out2 = false;
        recv_len1 = 0;
        recv_len2 = 0;
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
    ssize_t ret1 = 0;
    ssize_t ret2 = 0;
    uint32_t target_bytes1 = 0;
    uint32_t target_bytes2 = 0;
    uint32_t write_bytes_with_stream_id1;
    uint32_t write_bytes_with_stream_id2;
    int need_epoll_out = 0;
    bool skip1 = false;
    bool skip2 = false;

    bool quit1 = false;
    bool quit2 = false;
    /*if(c->pending_bytes1 == c->total_bytes1){
        c->start_time = time(NULL);
    }*/

    printf("------START SEND------\n");
    fflush(stdout);
    // Transmit messages as much as possible through this connection until we reach max_outstanding or no buffer space
    while (c->pending_bytes1 || c->pending_bytes2) {
        /*if(c->curr_buffer_send == 1){
            target_bytes = std::min(c->pending_bytes1, c->message_bytes1);
            ret = write(c->fd, c->buf1 + (c->total_bytes1 - c->pending_bytes1), std::min(target_bytes, (unsigned int)DATA_BLOCK_SIZE));
        }else{
            target_bytes = std::min(c->pending_bytes2, c->message_bytes2);
            ret = write(c->fd, c->buf2 + (c->total_bytes2 - c->pending_bytes2), std::min(target_bytes, (unsigned int)DATA_BLOCK_SIZE));
        }*/

        if(!skip1) {
            target_bytes1 = std::min(c->pending_bytes1, c->message_bytes1);
            write_bytes_with_stream_id1 = std::min(target_bytes1, (unsigned int)DATA_BLOCK_SIZE);
            write_bytes_with_stream_id1 |= 1u << 31;
            printf("BEFORE WRITE S1 %u %u %u \n", c->total_bytes1, c->pending_bytes1, (c->total_bytes1 - c->pending_bytes1));
            fflush(stdout);
            ret1 = write(c->fd, c->buf1 + (c->total_bytes1 - c->pending_bytes1), write_bytes_with_stream_id1);
            printf("AFTER WRITE S1 %u \n", (c->total_bytes1 - c->pending_bytes1));
            fflush(stdout);
            if(ret1 == 0) {
                skip1 = true;
                quit1 = true;
            }
        }

        if(!skip2) {
            target_bytes2 = std::min(c->pending_bytes2, c->message_bytes2);
            write_bytes_with_stream_id2 = std::min(target_bytes2, (unsigned int)DATA_BLOCK_SIZE);
            write_bytes_with_stream_id2 |= 1u << 30;
            printf("BEFORE WRITE S2 %u %u %u\n", (c->total_bytes2 - c->pending_bytes2), c->total_bytes2, c->pending_bytes2);
            fflush(stdout);
            ret2 = write(c->fd, c->buf2 + (c->total_bytes2 - c->pending_bytes2), write_bytes_with_stream_id2);
            printf("AFTER WRITE S2 %u \n", (c->total_bytes2 - c->pending_bytes2));
            fflush(stdout);
            if(ret2 == 0) {
                skip2 = true;
                quit2 = true;
            }
        }

        if (!skip1 && ret1 > 0) {

            c->pending_bytes1 -= ret1;
            printf("\tStream1 %u\n", c->pending_bytes1);
            fflush(stdout);

            if(c->pending_bytes1 == 0) {
                printf("Pending bytes 0 stream 1\n");
                fflush(stdout);
                skip1 = true;
                quit1 = true;
            }

            total_req_bytes[tid].fetch_add(ret1);
        }
        if(!skip2 && ret2 > 0) {
            c->pending_bytes2 -= ret2;
            printf("\tStream2 %u\n", c->pending_bytes2);

            if(c->pending_bytes2 == 0) {
                printf("Pending bytes 0 stream 2\n");
                fflush(stdout);
                skip2 = true;
                quit2 = true;
            }

            total_req_bytes[tid].fetch_add(ret2);
        }
        if(ret1 == 0) {
            // no buffer space
            printf("RET 0 STREAM 1\n");
            fflush(stdout);
            need_epoll_out |= (1u << 0);
            //break;
        }
        if(ret2 == 0) {
            // no buffer space
            printf("RET 0 STREAM 2\n");
            fflush(stdout);
            need_epoll_out |= (1u << 1);
            //break;
        }
        if(quit1 && quit2)
            break;
    }
    printf("------END SEND------\n\n");
    fflush(stdout);
    return need_epoll_out;
}

static inline void connection_recv(unsigned int tid, struct connection *c, uint32_t stream_id)
{
    ssize_t ret1 = 0;
    ssize_t ret2 = 0;
    bool wait_response1 = c->pending_bytes1 + c->message_bytes1 <= c->total_bytes1;
    bool wait_response2 = c->pending_bytes2 + c->message_bytes2 <= c->total_bytes2;

    uint32_t target_bytes_with_stream_id1, target_bytes_with_stream_id2;

    printf("------START RECV------\n");
    fflush(stdout);

    uint32_t target_bytes1 = 0;
    uint32_t target_bytes2 = 0;

    bool skip1 = false;
    bool skip2 = false;

    // Receive messages as much as possible through this connection if there are outstanding messages
    while (wait_response1 || wait_response2) {
        
        if(stream_id & 1u << 0 && !skip1) {
            target_bytes1 = short_response ? SHORT_RESPONSE_SIZE : c->message_bytes1;
            target_bytes_with_stream_id1 = std::min(target_bytes1, (unsigned int)DATA_BLOCK_SIZE);
            //printf("STREAM 0\n");
            target_bytes_with_stream_id1 = target_bytes1 | 1u << 31;
            printf("READ RET STREAM 1 BEFORE %lu %u\n", ret1, c->pending_bytes1);
            fflush(stdout);
            ret1 = read(c->fd, c->buf1 + c->recv_len1, target_bytes_with_stream_id1);
            printf("READ RET STREAM 1 AFTER %lu %u\n", ret1, c->pending_bytes1);
            fflush(stdout);
            if(ret1 == 0)
                skip1 = true;
        }
        if(stream_id & 1u << 1 && !skip2) {
            target_bytes2 = short_response ? SHORT_RESPONSE_SIZE : c->message_bytes2;
            target_bytes_with_stream_id2 = std::min(target_bytes2, (unsigned int)DATA_BLOCK_SIZE);
            //printf("STREAM 1\n");
            target_bytes_with_stream_id2 = target_bytes_with_stream_id2 | 1u << 30;
            printf("READ RET STREAM 2 BEFORE %lu %u\n", ret2, c->pending_bytes2);
            fflush(stdout);
            ret2 = read(c->fd, c->buf2 + c->recv_len1, target_bytes_with_stream_id2);
            printf("READ RET STREAM 2 AFTER %lu %u\n", ret2, c->pending_bytes2);
            fflush(stdout);
            if(ret2 == 0)
                skip2 = true;
        }

        //printf("RECEIVED %lu %u %u\n", ret, c->pending_bytes1, c->recv_len);
        if (ret1 > 0) {
            c->recv_len1 += ret1;
            total_resp_bytes[tid].fetch_add(ret1);
        }
        if(ret2 > 0) {
            c->recv_len2 += ret2;
            total_resp_bytes[tid].fetch_add(ret2);
        }
        if(ret1 == 0 && ret2 == 0) {
            // no more data
            break;
        }
        if (stream_id & 1u << 0 && !skip1 && c->recv_len1 >= target_bytes1) {
            printf("->>> before recv 1 increase %u %u %u %u\n", c->recv_len1, target_bytes1, c->pending_bytes1, c->message_bytes1);
            fflush(stdout);
            c->recv_len1 -= target_bytes1;
            c->pending_bytes1 += c->message_bytes1;
            printf("->>> after recv 1 increase %u %u %u %u\n", c->recv_len1, target_bytes1, c->pending_bytes1, c->message_bytes1);
            fflush(stdout);
        }

        if (stream_id & 1u << 1 && !skip2 && c->recv_len2 >= target_bytes2) {
            printf("->>> before recv 2 increase %u %u %u %u\n", c->recv_len2, target_bytes2, c->pending_bytes2, c->message_bytes2);
            fflush(stdout);
            c->recv_len2 -= target_bytes2;
            c->pending_bytes2 += c->message_bytes2;
            printf("->>> after recv 2 increase %u %u %u %u\n", c->recv_len2, target_bytes2, c->pending_bytes2, c->message_bytes2);
            fflush(stdout);
        }
    }
    printf("------END RECV------\n\n");
    fflush(stdout);
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
        //fprintf(stderr, "Failed to create epoll\n");
        return;
    }

    for (unsigned int i = 0; i < t_nr_flows; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            //fprintf(stderr, "Failed to create socket\n");
            perror("\n");
            return;
        }

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(t_server_port);
        server_addr.sin_addr.s_addr = server_ip_addr.s_addr;
        if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            //fprintf(stderr, "Failed to connect to server\n");
            perror("connect");
            close(fd);
            return;
        }

        // close(fd);

        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
            //fprintf(stderr, "Failed to set non-blocking\n");
            close(fd);
            return;
        }

        ev.events = EPOLLIN | EPOLLOUT | EPOLLERR;
        ev.data.ptr = new connection(fd, message_bytes_short, message_bytes_long, max_outstanding);

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            //fprintf(stderr, "Failed to add fd to epoll\n");
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

        //printf("BEFORE WAIT\n");
        fflush(stdout);
        int nfds = epoll_wait(epfd, events, 128, -1);
        //printf("AFTER WAIT %d\n", nfds);
        fflush(stdout);

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
                //fprintf(stderr, "EPOLLERR\n");
                conn_fds.remove(c->fd);
                // remove from epoll
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
                close(c->fd);
                continue;
            }

            int ret = connection_events(tid, c, events[i].events, stream_id);
            printf("RET %d\n", ret);
            fflush(stdout);
            if (!(ret & 1u << 0) && !c->no_epoll_out1) {
                printf("EPOLL_CTL STREAM 1\n");
                fflush(stdout);
                ev.events = EPOLLIN | EPOLLERR;
                ev.data.ptr = c;
                int epoll_ev = EPOLL_CTL_MOD;
                epoll_ev |= (1u << 31);
                if (epoll_ctl(epfd, epoll_ev, c->fd, &ev) < 0) {
                    //fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                printf("EPOLL_CTL STREAM 1 AFTER\n");
                fflush(stdout);
                c->no_epoll_out1 = 1;
            } else if (ret & 1u << 0 && c->no_epoll_out1) {
                printf("EPOLL_CTL STREAM 1 OUT\n");
                fflush(stdout);
                ev.events = EPOLLIN | EPOLLERR | EPOLLOUT;
                ev.data.ptr = c;
                int epoll_ev = EPOLL_CTL_MOD;
                epoll_ev |= (1u << 31);
                if (epoll_ctl(epfd, epoll_ev, c->fd, &ev) < 0) {
                    //fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                printf("EPOLL_CTL STREAM 1 OUT AFTER\n");
                fflush(stdout);
                c->no_epoll_out1 = 0;
            }
            
            if (!(ret & 1u << 1) && !c->no_epoll_out2) {
                printf("EPOLL_CTL STREAM 2\n");
                fflush(stdout);
                ev.events = EPOLLIN | EPOLLERR;
                ev.data.ptr = c;
                int epoll_ev = EPOLL_CTL_MOD;
                epoll_ev |= (1u << 30);
                if (epoll_ctl(epfd, epoll_ev, c->fd, &ev) < 0) {
                    //fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                c->no_epoll_out2 = 1;
            } else if (ret & 1u << 1 && c->no_epoll_out2) {
                printf("EPOLL_CTL STREAM 2 OUT\n");
                fflush(stdout);
                ev.events = EPOLLIN | EPOLLERR | EPOLLOUT;
                ev.data.ptr = c;
                int epoll_ev = EPOLL_CTL_MOD;
                epoll_ev |= (1u << 30);
                if (epoll_ctl(epfd, epoll_ev, c->fd, &ev) < 0) {
                    //fprintf(stderr, "Failed to add fd to epoll\n");
                    return;
                }
                c->no_epoll_out2 = 0;
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