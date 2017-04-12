#ifndef fs_hpp
#define fs_hpp

#include "fs_server.h"
#include "rw_lock.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <thread>

#include <cstdlib>
#include <cstring>
#include <string>

#include <array>
#include <iostream>

#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <vector>
#include <sstream>
#include <fstream>
#include <iterator>
#include <mutex>
#include <condition_variable>

void fs_init(int server_port);
void handle_request(int sock);
void send_data(int sock, std::string return_session, std::string sequence, std::string pword);
void traverse(fs_inode *root, std::unordered_set<unsigned int> *used);
bool dfs(fs_inode &inode, std::vector<std::string> dirs, int i, unsigned int &block_num, bool read_last);
int check_session(std::string session, std::string sequence, std::string username);

static int session_num = 0;

std::unordered_map<unsigned int, unsigned int> session_sequence;
std::unordered_map<unsigned int, std::string> session_username;
std::queue<unsigned int> avi_blocks;
std::mutex session_num_lock;
std::mutex avi_block_lock;
std::unordered_map<std::string, std::string> password_map;
std::unordered_map<unsigned int,rwlock*> lock_map;

#endif /* fs_h */















