#include <cstdio>
#include <stdlib.h> 
#include <fstream>
#include <iostream>
#include <sstream>
#include <string.h>
#include <string>
#include <vector>
#include <bits/stdc++.h> 
#include <boost/algorithm/string.hpp>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <chrono>
#include <unordered_map>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h> 
#include <thread> 


#define MAX_CONNECTIONS 15
#define BUFF_LEN    1024
#define PARSE_ONLY_HOST 0
#define PARSE_ONLY_PORT 1

#define TIMEOUT_SEC 10
#define TIMEOUT_USEC 0
using namespace std;
struct file_cache 
{
    chrono::system_clock::time_point time_of_creation;
    mutex file_mutex;
    file_cache(chrono::system_clock::time_point c)
    {
        time_of_creation = c;
    }
};


int cache_timeout_sec;
int port_number;
vector<string> blacklist;
hash<string> hasher;

// File cache stuff
unordered_map<size_t, file_cache*>* file_cache_map = new unordered_map<size_t, file_cache*> ();
mutex file_cache_mutex;

// Address cache stuff
unordered_map <string, hostent*>* host_address_cache_map = new unordered_map<string, hostent*> ();
mutex host_address_cache_mutex;
void exit_with_msg(const char* msg){
    perror(msg);
    // TODO close sockets
    exit(EXIT_FAILURE);
}
void check_arguments(int argc){
    if (argc != 3)
        exit_with_msg("Command has to be ./webproxy <port number> <timeout>\n");
}

void init_server_parameters(char* argv[]){
    cache_timeout_sec = atoi(argv[2]);
    port_number = atoi(argv[1]);
}

void init_blacklist(){
    ifstream file("blacklist.txt");
    string line;
    while(getline(file, line))
        blacklist.push_back(line);
    printf("Parsed %d sites in the blacklist\n", (int)blacklist.size()); // DEBUG
}

int create_proxy_socket(){
    int socket_proxy = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_proxy == -1)
        exit_with_msg("create_proxy_socket: Could not create a socket\n");
    
    int enable_reuse = 1;
    if (setsockopt(socket_proxy, SOL_SOCKET, SO_REUSEADDR, &enable_reuse, sizeof(int)) < 0)
        exit_with_msg("create_proxy_socket: SO_REUSEADDR failed\n");
    //puts("create_proxy_socket: Created a socket"); // DEBUG

    return socket_proxy;
}

struct sockaddr_in create_proxy_sockaddr(int socket_proxy){
    struct sockaddr_in proxy;
    proxy.sin_family = AF_INET;
    proxy.sin_addr.s_addr = INADDR_ANY;
    proxy.sin_port = htons(port_number);

    if (bind(socket_proxy, (struct sockaddr*)&proxy, sizeof(proxy)) < 0)
        exit_with_msg("create_proxy_sockaddr: failed to bind\n");
    //puts ("create_proxy_sockaddr: Bind done"); // DEBUG
    return proxy;
}

int receive_request(int socket_client, char *msg){
    int recv_len = recv(socket_client, msg, BUFF_LEN, 0);
    //if (recv_len == 0)
        //puts("receive_request: client disconnected\n"); // DEBUG
    //else
     if (recv_len == -1)
        puts("receive_request: recv failed\n"); 
    return recv_len;

}

int send_to_client(int socket_client, const void *msg, size_t msg_len){
    int write_bytes = write(socket_client, msg, msg_len);
    if (write_bytes <= 0)
        printf("send_to_client: Failed to send msg = %s\n", (const char*)msg);
    return write_bytes;
}

void send_to_client_with_error_handling(int socket_client, const void *msg, size_t msg_len){
    int bytes = send_to_client(socket_client, msg, msg_len);
    if (bytes <= 0){
        puts("send_to_client_with_error_handling: Failed to send GET response to client");
        string error = "HTTP/1.1 404 Not Found\r\nContent-Type text/plain\r\nContent-Length: 21\r\n\r\nStatus: 404 Not Found ";
        send_to_client(socket_client, error.c_str(), error.length());
    }
}
bool is_cache_timed_out(file_cache* cache_entry){
    chrono::system_clock::time_point cur_time = chrono::system_clock::now();
    auto cache_live_time = (cur_time - cache_entry->time_of_creation); // How long this cache has been living
    int cache_live_time_sec = (int)chrono::duration_cast<chrono::seconds>(cache_live_time).count();

    return cache_live_time_sec >= cache_timeout_sec;
}

size_t get_file_hash_from_request(vector<string> request_lines) {
    vector<string> get_request_parts;
    boost::split(get_request_parts, (char*)request_lines[0].c_str(), boost::is_any_of(" "));
    //printf("get_file_hash_from_request, file_name=%s\n", get_request_parts[1].c_str()); // DEBUG
    return hasher(get_request_parts[1]);
}

bool has_valid_cache(int socket_client, vector<string> request_lines){
    
    size_t file_hash = get_file_hash_from_request(request_lines);
    auto cache_entry = file_cache_map -> find(file_hash);

    if (cache_entry == file_cache_map ->end())
        return false; // Hash not in cache
    else if (is_cache_timed_out(cache_entry->second)) {
        // Delete timed out cache
        file_cache_map ->erase(file_hash);
        return false; // Cache timed out
    }
    else
        return true;
}

void send_response_from_cache(int socket_client, vector<string> request_lines){
    size_t file_hash = get_file_hash_from_request(request_lines);
    auto cache_entry = file_cache_map -> find(file_hash);

    cache_entry -> second -> file_mutex.lock();
    
    
    
    char file_name[50];
    sprintf(file_name, "cache/%u.txt", (unsigned int)file_hash);
    ifstream cache_file(file_name);
    stringstream cache_stream;
    cache_stream << cache_file.rdbuf();
    cache_entry -> second -> file_mutex.unlock();
    printf("Read from cache file %u.txt for socket_client = %d \n", (unsigned int) file_hash, socket_client); // DEBUG
    string response = cache_stream.str();
    send_to_client_with_error_handling(socket_client, response.c_str(), response.length());
}

string parse_host(vector<string> request_lines, int option){
    // PARSE_ONLY_HOST will return the host without the port number (string)
    // PARSE_ONLY_PORT will return only the port number (string)
    string host = ""; // Host with port number in one string
    for (string request_line : request_lines)
        if (!strncmp(request_line.c_str(), "Host:", 5))
            host = request_line.substr(6, request_line.length() -6 - 1);
    vector<string> host_splitted;
    boost::split(host_splitted, host, boost::is_any_of(":"));
    if (option == PARSE_ONLY_HOST)
        return host_splitted[0]; // return only host 
    else if (host_splitted.size() == 2)
        return host_splitted[1]; // Return only port number
    else 
        return "80"; // Return default port
}

struct hostent* get_host(vector<string> request_lines){
    string host_str = parse_host(request_lines, PARSE_ONLY_HOST);
    host_address_cache_mutex.lock();
    struct hostent* host;
    if (host_address_cache_map -> find(host_str) == host_address_cache_map -> end()){
        // We don't have a cache for this host
        host = gethostbyname(host_str.c_str());
        host_address_cache_map->insert({host_str, host});
        //printf("get_host: added new host to cache => %s\n", host_str.c_str()); // DEBUG
    }
    else {
        // Retrieve the host from the cache
        host = host_address_cache_map->find(host_str)->second;
        //printf("get_host: host exists in cache => %s\n", host_str.c_str()); // DEBUG
    } 

    host_address_cache_mutex.unlock();
    return host;
}

bool is_host_blacklisted(struct hostent* host){
    // We need to test for both host (could be DNS) and IP address
    //Parse IP out of host
    string ip_address_str;
    string host_str;
    if (host != NULL && host ->h_addr != NULL){
        host_str = host->h_name;
        struct in_addr ip_address;
        bcopy(host->h_addr, (char*)&ip_address, sizeof(ip_address));
        string ip_temp (inet_ntoa(ip_address));
        ip_address_str = ip_temp;
    }

    if (find(blacklist.begin(), blacklist.end(), host_str) != blacklist.end())
        return true; // Host is blacklisted
    else if (find(blacklist.begin(), blacklist.end(), ip_address_str) != blacklist.end())
        return true; // Host's ip address is blacklisted
    else
        return false;
}

void send_host_blacklisted_response(int socket_client){
    puts("Blacklisted host. Will reply with Forbidden"); // DEBUG
    string error = "HTTP/1.1 403 Forbidden\r\nContent-Type text/plain\r\nContent-Length: 21\r\n\r\nStatus: 403 Forbidden ";
    send_to_client(socket_client, error.c_str(), error.length());
}


bool is_host_invalid(struct hostent* host){
    return host == NULL || host ->h_name == NULL || host->h_addr == NULL;
}


void send_invalid_host_response(int socket_client, vector<string> request_lines){
    puts("send_invalid_host_name: Host is invalid"); // DEBUG
    file_cache_map->erase(get_file_hash_from_request(request_lines));
    string error = "HTTP/1.1 404 Not Found\r\nContent-Type text/plain\r\nContent-Length: 21\r\n\r\nStatus: 404 Not Found ";
    send_to_client(socket_client, error.c_str(), error.length());
}

void setup_timeout_for_socket(int socket_host){
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = TIMEOUT_USEC;
    if (setsockopt(socket_host, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)))
        puts("setup_timeout: Error setting up socket for timeout");

}

void handle_failed_host_socket(int socket_client, int socket_host, vector<string> request_lines){
    close(socket_host);
    puts("handle_failed_host_socket: Failed to create a socket for host. Will abort");
    file_cache_map->erase(get_file_hash_from_request(request_lines));
    string error = "HTTP/1.1 500 Internal Server Error\r\nContent-Type text/plain\r\nContent-Length: 33\r\n\r\nStatus: 500 Internal Server Error ";
    send_to_client(socket_client, error.c_str(), error.length());
}

void handle_failed_connection_to_host(int socket_client, int socket_host, vector<string> request_lines){
    close(socket_host);
    puts("handle_failed_connection_to_host: Failed to connect to server");
    file_cache_map->erase(get_file_hash_from_request(request_lines));
    string error = "HTTP/1.1 500 Internal Server Error\r\nContent-Type text/plain\r\nContent-Length: 33\r\n\r\nStatus: 500 Internal Server Error ";
    send_to_client(socket_client, error.c_str(), error.length());

}
int connect_to_host(int socket_client,struct hostent *host, vector<string> request_lines){
    struct sockaddr_in sockaddr_host;
    memset(&sockaddr_host, 0, sizeof(sockaddr_host));
    sockaddr_host.sin_family = AF_INET;
    sockaddr_host.sin_port = htons(stoi(parse_host(request_lines, PARSE_ONLY_PORT)));
    memcpy(&sockaddr_host.sin_addr, host->h_addr, host->h_length);
    int socket_host = create_proxy_socket();
    setup_timeout_for_socket(socket_host);
    if (socket_host < 0)
        {
            handle_failed_host_socket(socket_client, socket_host, request_lines);
            return -1;
        }
    else if (connect(socket_host, (struct sockaddr*) &sockaddr_host, sizeof(sockaddr_host)) < 0) {
            handle_failed_connection_to_host(socket_client, socket_host, request_lines);
            return -1;
    }
    
    //printf("connect_to_host: Connected to host sucessfully, socket_host=%d, socket_client=%d\n", socket_host, socket_client); // DEBUG
    return socket_host;
}

int forward_request_to_host(int socket_client, struct hostent *host,const char *client_request,vector<string> request_lines){
    int socket_host = connect_to_host(socket_client, host, request_lines);
    if (socket_host == -1)
        return -1; // No connection so terminate
    // Recreate the original request of the client from vector<string> to string
    //printf("forward_request_to_host: client_request length = %s\n" ,client_request); //DEBUG
    int bytes = send_to_client(socket_host, client_request, strlen(client_request));
    if (bytes <= 0){
        file_cache_map->erase(get_file_hash_from_request(request_lines));
        string error = "HTTP/1.1 500 Internal Server Error\r\nContent-Type text/plain\r\nContent-Length: 33\r\n\r\nStatus: 500 Internal Server Error ";
        send_to_client(socket_client, error.c_str(), error.length());
        return -1;
    }

    //printf("forward_request_to_host: forwarded request to socket_host = %d, socket_client = %d\n", socket_host, socket_client); // DEBUG
    return socket_host;
}

string get_response_from_host(int socket_host){
    string response;
    char c; // We will get response character by character
    while(read(socket_host, &c, 1))
        response += c;
    return response;
}

void write_response_to_cache(string response, vector<string> request_lines){
    char filename[50];
    sprintf(filename, "cache/%u.txt", (unsigned int)get_file_hash_from_request(request_lines));
    //printf("write_response_to_cache: Caching to file %s\n", filename); // DEBUG
    ofstream out_cache_file(filename);
    out_cache_file << response;
}

struct prefetch_args {
     const char* main_page;
     const char* base_host;
};

bool is_a_url(string file_to_be_fetched){
    // Does it start or http or https
    return file_to_be_fetched.substr(0, 4).compare("http") == 0
        || file_to_be_fetched.substr(0, 5).compare("https") == 0;
}

string parse_host_from_url(string url){
    // http://netsys.cs.colorado.edu/favicon.ico
    // https://tools.ietf.org/html/rfc8312.txt
    // We want to extract
    // netsys.cs.colorado.edu
    int index_of_first_slash = url.find_first_of("/");
    return url.substr(index_of_first_slash+2, url.find_first_of("/", index_of_first_slash+2) - (index_of_first_slash + 2));
}
void prefetch(string file_path, string host, string client_request, int socket_client) {
    printf("prefetch: no modification client_request, \n-------\n%s\n-------\n", client_request.c_str());

    string prefetch_request = "GET " + file_path;
    handle_client_request(socket_client, prefetch_request.c_str());
    /*printf("prefetch: file_path=%s, host=%s\n", file_path.c_str(), host.c_str());
    //int get_index = client_request.find_first_of("GET");
    //client_request.erase(get_index+4, (client_request.find_first_of(" ", get_index+4) - (get_index+4)));
    //client_request.insert(get_index+4, file_path);
    //printf("prefetch: after replacing GET, client_request=\n-----------\n%s\n--------\n", client_request.c_str());
    int host_index = client_request.find_first_of("Host:");
    client_request.erase(host_index+5, (client_request.find_first_of(" ", host_index+5) - (host_index + 5)));
    //client_request.insert(host_index+5,host);
    printf("prefetch: after replacing host, client_request=\n-----------\n%s\n--------\n", client_request.c_str());
    */

}
void handle_prefetching(string host, string response, string client_request, int socket_client){
    //printf("handle_prefetching: Inside prefetch thread\n"); // DEBUG
    // Example
    // <a href="images/wine3.jpg">JPG</a> 
    int i = 0;
    int href_index = 0;
    //printf("handle_prefetching: response=%s\n", response.c_str()); // DEBUG
    while((href_index=response.find("<a href=", i)) != -1){
        int first_quote_index = response.find_first_of("\"", href_index);
        int second_quote_index = response.find_first_of("\"", first_quote_index+1);
        string href_link_str = response.substr(first_quote_index+1, (second_quote_index-first_quote_index-1));
        if (is_a_url(href_link_str))
            prefetch(href_link_str, parse_host_from_url(href_link_str), client_request, socket_client);
        else
            prefetch(host + "/" + href_link_str, host, client_request, socket_client);

        i = second_quote_index;
    }
    
    //return 0;
}

void send_response_from_host(int socket_client, const char* client_request, vector<string> request_lines){
    // There is no cache, we have to get a fresh response
    // Send a request to the destination (host), cache the response and send it to the user
    file_cache* new_cache = new file_cache(chrono::system_clock::now());

    new_cache->file_mutex.lock();
    struct hostent* host = get_host(request_lines);

    if (is_host_invalid(host))
        send_invalid_host_response(socket_client, request_lines);
    else if (is_host_blacklisted(host))
        send_host_blacklisted_response(socket_client);
    else
    {
        int socket_host = forward_request_to_host(socket_client, host, client_request, request_lines ); // Get response from the actual server
        if (socket_host == -1 )
            return;
        // Extra credit: prefetching
        string response = get_response_from_host(socket_host);
        thread prefetch_thread(handle_prefetching, host->h_name, response, client_request,socket_client);
        prefetch_thread.detach();
       // printf("send_response_from_host: Received response from socket_host=%d. Will proceed to write it to cache \n", socket_host); // DEBUG
        write_response_to_cache(response, request_lines);
        new_cache -> time_of_creation = chrono::system_clock::now();
        new_cache ->file_mutex.unlock();
        send_to_client_with_error_handling(socket_client, response.c_str(), response.length());
    }
    
    file_cache_mutex.lock();
    file_cache_map->insert({get_file_hash_from_request(request_lines), new_cache});
    file_cache_mutex.unlock();
}

bool is_not_get_request(vector<string> request_lines){
    return strncmp(request_lines[0].c_str(), "GET", 3) != 0;
}

void send_not_get_request_error(int socket_client){
    // If this request is anything else but GET
    // The GET requests is processed in handle_new_connection
    //puts("Received a request that is not GET. Will reply with 400 Bad Request"); // DEBUG
    string error_msg = "HTTP/1.1 400 Bad Request\r\nContent-Type text/plain\r\nContent-Length: 23\r\n\r\nStatus: 400 Bad Request ";
    send_to_client(socket_client, error_msg.c_str(), error_msg.length());
}

void handle_client_request(int socket_client, const char *client_request){
    vector<string> request_lines;
        boost::split(request_lines, client_request, boost::is_any_of("\n"));
        //First element of msg_parts is Type of Request
        //Second is URI
        //Third is version
        if (is_not_get_request(request_lines))
            send_not_get_request_error(socket_client);
        
        else {
            // It's a GET request
            if (has_valid_cache(socket_client, request_lines))
                send_response_from_cache(socket_client, request_lines);
            else // Cache is either does not exist or timed out
                send_response_from_host(socket_client, client_request,request_lines);
        }
}
void* handle_new_connection(void *socket){
    int socket_client = *(int*)socket;
    char client_request[BUFF_LEN];
    int msgLen;
    while ((msgLen = receive_request(socket_client, client_request) > 0)){
        //printf("handle_new_connection: client_request=%s\n", client_request); // DEBUG
        handle_client_request(socket_client, client_request);
        
    }

    free(socket);

    return 0;
}
void accept_incoming_connections(int socket_proxy, struct sockaddr_in proxy){
    int listen_result = listen(socket_proxy, MAX_CONNECTIONS);
    if (listen_result != 0)
        exit_with_msg("accept_incoming_connections: failed to listen\n");
    puts("Waiting for connections"); // DEBUG
    struct sockaddr_in client;
    int client_size = sizeof(struct sockaddr_in);
    int socket_client;
    while ((socket_client = accept(socket_proxy, (struct sockaddr *) &client, (socklen_t*)&client_size))){
        //puts ("accept_incoming_connections: New connection accepted"); // DEBUG
        pthread_t new_connection_thread;
        int *socket_copied = (int*)malloc(1);
        *socket_copied = socket_client;
        if (pthread_create(&new_connection_thread, NULL, handle_new_connection, (void*) socket_copied) < 0)
            exit_with_msg("accept_incoming_connections: Failed to create a new thread\n");
    }
    if (socket_client < 0)
        exit_with_msg("accept_incoming_connectin: Failed to accept a new connection\n");
}
int main(int argc, char* argv[]){
    check_arguments(argc);
    init_server_parameters(argv);
    init_blacklist();
    int socket_proxy = create_proxy_socket();
    struct sockaddr_in proxy = create_proxy_sockaddr(socket_proxy);
    accept_incoming_connections(socket_proxy, proxy);
}