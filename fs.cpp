#include "fs.h"
#include <cassert>



void send_data(int sock, std::string return_session, std::string sequence, std::string pword){
    return_session += " " + sequence;
    const char* send_data = return_session.c_str();
    unsigned int send_size = 0;
    char* send_buf = (char*) fs_encrypt(pword.c_str(), (void*)send_data, strlen(send_data)+1, &send_size);
    std::string header = std::to_string(send_size);
    // send cleartext header first
    send(sock, header.c_str(), header.size() + 1, 0);
    // send the encrypted data, format: <size><NULL>
    send(sock, send_buf, send_size, 0);
    delete [] send_buf;
}

std::vector<std::string> split(std::string str, char delimiter) {
    
    str = str.substr(1,str.size()-1);//delete the first '/' to avoid start with a white space
    std::vector<std::string> internal;
    std::stringstream ss(str); // Turn the string into a stream.
    std::string tok;
    
    while(getline(ss, tok, delimiter)) {
        internal.push_back(tok);
    }
    return internal;
}

void traverse(fs_inode *root, std::unordered_set<unsigned int> *used){
    for(int i = 0;i < root->size;i++){
        unsigned int cur = root->blocks[i];
        used->insert(cur);
        if(root->type == 'd'){
            fs_direntry dir_entries[FS_DIRENTRIES];
            disk_readblock(cur, dir_entries);
            for(int j = 0;j < FS_DIRENTRIES;j++){
                unsigned int cur_inode_block = dir_entries[j].inode_block;
                if(cur_inode_block != 0){
                    used->insert(cur_inode_block);
                    fs_inode cur_inode;
                    lock_map[cur_inode_block] = new rwlock();
                    disk_readblock(cur_inode_block, &cur_inode);
                    traverse(&cur_inode,used);
                }
            }
        }
    }
}

bool dfs(fs_inode &inode, std::vector<std::string> dirs, int i, unsigned int &block_num, bool read_last, std::string username){
    if(dirs.size() == 0) return true;
    if(inode.type == 'd'){
        for(int j = 0; j < inode.size; j++){
            fs_direntry dir_entries[FS_DIRENTRIES];
            disk_readblock(inode.blocks[i], dir_entries);
            for(int k = 0; k < FS_DIRENTRIES; ++k){
                if(dir_entries[k].inode_block && !strcmp(dirs[i].c_str(), dir_entries[k].name)){
                    //we may need to get the W lock of the last inode
                    if(i == dirs.size()-1 && !read_last){
                        lock_map[dir_entries[k].inode_block]->writerStart();
                    }
                    else{
                        lock_map[dir_entries[k].inode_block]->readerStart();
                    }
                    
                    lock_map[block_num]->readerFinish();
                    
                    disk_readblock(dir_entries[k].inode_block, &inode);
                    if(strcmp(inode.owner, username.c_str())){
                        if(i == dirs.size()-1 && !read_last){
                            lock_map[dir_entries[k].inode_block]->writerFinish();
                        }
                        else{
                            lock_map[dir_entries[k].inode_block]->readerFinish();
                        }
                        return false;
                    }
                    block_num = dir_entries[k].inode_block;
                    if(i == dirs.size()-1) return true;
                    if(dfs(inode, dirs, i+1, block_num, read_last)) return true;
                }
            }
        }
    }
    lock_map[block_num]->readerFinish();//if stop in the middle, release the lock of the current layer
    return false;
}

int check_session(std::string session, std::string sequence, std::string username){
    if(session_sequence.find(stoi(session)) == session_sequence.end()){
        return -1;
    }
    if(session_username[stoi(session)] != username){
        return -1;
    }
    if(session_sequence[stoi(session)] >= stoi(sequence)){
        return -1;
    }
    session_sequence[stoi(session)] = stoi(sequence);
    return 0;
}

void fs_init(int server_port){
    //traverse from root to determine avilable blocks;
    fs_inode root;
    disk_readblock(0, &root);
    std::unordered_set<unsigned int> used;
    lock_map[0] = new rwlock();
    traverse(&root, &used);
    for(int i = 1;i < FS_DISKSIZE;i++) {
        if(used.find(i) == used.end()){
            avi_blocks.push(i);
        }
    }
    //create socket
    int sock;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "opening stream socket " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    
    //set
    int yes = 1;
    int rc;
    rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    
    //bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(server_port);
    
    bind(sock, (struct sockaddr*) &addr, sizeof(addr));
    
    //listen
    rc = listen(sock, 10);
    socklen_t len = sizeof(addr);
    
    // get the port number if it is not specified
    getsockname(sock, (struct sockaddr *)&addr, &len);
    
    // print the port number
    std::cout << "\n@@@ port " << ntohs(addr.sin_port) << std::endl;
    
    while(true){
        int client_sock = accept(sock, nullptr, nullptr);
        std::thread t1(handle_request, client_sock);
        t1.detach();
    }
}

void handle_request(int sock){
    // reading the cleartext request header(un-encrypted)
    // format: <username> <size><NULL>
    std::string username, size_str;
    char d = 'a';
    while(d != ' '){
        recv(sock, &d, 1, 0);
        username += d;
    }
    username = username.substr(0, username.size()-1);
    
    while(d != '\0'){
        recv(sock, &d, 1, 0);
        size_str += d;
    }
    size_str = size_str.substr(0, size_str.size()-1);
    
    unsigned int size = stoi(size_str);
    //check password
    if(password_map.find(username) == password_map.end()){
        //invalid username
        close(sock);
        return;
    }
    std::string pword = password_map[username];
    
    //receive encrypted request msg
    unsigned int buf_size = 0;
    char encrypted_data[size];
    recv(sock, &encrypted_data, size, 0);
    
    char* rec_buf = (char*) fs_decrypt(pword.c_str(), &encrypted_data, stoi(size_str), &buf_size);
    if(!rec_buf){ //  decryption fails, ie,wrong password
        //        close(sock);
        delete [] rec_buf;
        return;
    }
    std::vector<std::string> request_data;
    std::string temp;
    for(int k = 0; k < buf_size; ++k){
        if(rec_buf[k] == ' ' || rec_buf[k] == '\0'){
            request_data.push_back(temp);
            temp.clear();
            continue;
        }
        temp += rec_buf[k];
    }
    //deallocate memory
    delete [] rec_buf;
    
    std::string request_name = request_data[0];
    
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    if(request_name == "FS_SESSION"){
        assert(request_data.size() == 3);
        std::string session = request_data[1];
        std::string sequence = request_data[2];
        if(stoi(session)){
            // FS_SESSION request's session number MUST be 0 to be consider valid
            close(sock);
            return;
        }
        // return format: <session> <sequence><NULL>
        
        session_sequence[session_num] = stoi(sequence);
        session_username[session_num] = username;
        session_num_lock.lock();
        std::string return_session = std::to_string(session_num++);
        session_num_lock.unlock();
        // response to client
        send_data(sock, return_session, sequence, pword);
        close(sock);
    }
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    else if(request_name == "FS_READBLOCK"){
        std::string session = request_data[1];
        std::string sequence = request_data[2];
        std::string pathname = request_data[3];
        std::string block = request_data[4];
        
        
    }
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    else if(request_name == "FS_WRITEBLOCK"){
        
    }
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    else if(request_name == "FS_CREATE"){
        if(request_data.size() != 5){
            close(sock);
            return;
        }
        std::string session = request_data[1];
        std::string sequence = request_data[2];
        std::string pathname = request_data[3];
        std::string type = request_data[4];
        
        avi_block_lock.lock();
        if(avi_blocks.empty()){
            avi_block_lock.unlock();
            close(sock);
            return;
        }
        avi_block_lock.unlock();
        // error checking
        if(type.size() != 1 || (type[0] != 'f' && type[0] != 'd')){
            return;
        }
        //check session
        if(check_session(session, sequence, username)){
            close(sock);
            return;
        }
        
        // create directoty
        if(pathname.empty() || pathname[0] != '/' || pathname[pathname.size()-1] == '/'){
            close(sock);
            return;
        }
        std::vector<std::string> dirs = split(pathname, '/');
        
        std::string dir = dirs[dirs.size()-1];//pop the last
        dirs.pop_back();//one out
        
        if(dirs.size() == 0){
            lock_map[0]->writerStart();//if root is the parent, get the W lock.
        }
        else{
            lock_map[0]->readerStart();
        }
        
        fs_inode inode;
        disk_readblock(0, &inode);
        //--------------remember the parent block and direntry block to write back.
        unsigned int inode_block_num = 0;
        unsigned int dir_block_num = 0;
        //--------------
        if(!dfs(inode, dirs, 0, inode_block_num, false)){//find the parent inode
            close(sock);
            return;
        }
        
        //the second last one must be an directory
        if(inode.type == 'f' || avi_blocks.empty()){
            lock_map[inode_block_num]->writerFinish();//release the W lock of the parent first.
            close(sock);
            return;
        }
        
        
        //checking if this f/d has already exists and try to find an empty direntry.
        fs_direntry *di;
        fs_direntry dir_entries[FS_DIRENTRIES];
        bool found = false;
        for(int i = 0;i < inode.size;i++){
            disk_readblock(inode.blocks[i], dir_entries);
            for(int j = 0;j < FS_DIRENTRIES;j++){
                if(dir_entries[j].inode_block && dir_entries[j].name == dir){
                    //duplicate, stop
                    lock_map[inode_block_num]->writerFinish();//release the W lock of the parent first.
                    close(sock);
                    return;
                }
                if(dir_entries[j].inode_block == 0){
                    //found
                    if(!found){
                        di = &dir_entries[j];
                        found = true;
                        dir_block_num = inode.blocks[i];
                    }
                }
            }
        }
        
        if(!found){
            //try to allocate a new data block
            if(inode.size == FS_MAXFILEBLOCKS-1 || avi_blocks.size()<2){
                //no more place, create failed
                lock_map[inode_block_num]->writerFinish();//release the W lock of the parent first.
                close(sock);
                return;
            }
        }
        
        //now, we know we are ok to create, create new inode and write to disk
        fs_inode new_inode;
        strcpy(new_inode.owner, username.c_str());
        new_inode.size = 0;
        new_inode.type = type[0];
        unsigned int assign_block = avi_blocks.front();
        lock_map[assign_block] = new rwlock();//assign the new rw lock
        avi_blocks.pop();
        disk_writeblock(assign_block, &new_inode);
        
        //change directory and write to disk
        if(!found){
            //when creating a new direntry block initial to be all 0.
            for(int i = 0;i < FS_DIRENTRIES; i++){
                dir_entries[i].inode_block = 0;
            }
            
            di = &dir_entries[0];
            dir_block_num = avi_blocks.front();
            avi_blocks.pop();
        }
        di->inode_block = assign_block;
        strcpy(di->name, dir.c_str());
        disk_writeblock(dir_block_num, dir_entries);
        
        //if we need to change inode, we also write it back to disk
        if(!found){
            inode.size++;
            inode.blocks[inode.size-1] = dir_block_num;
            disk_writeblock(inode_block_num, &inode);
        }
        
        lock_map[inode_block_num]->writerFinish();//release the W lock of the parent.
        // response to client
        send_data(sock, session, sequence, pword);
        close(sock);
    }
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    /*--------------------------------------------*/
    else if (request_name == "FS_DELETE"){
        if(request_data.size() != 4){
            close(sock);
            return;
        }
        std::string session = request_data[1];
        std::string sequence = request_data[2];
        std::string pathname = request_data[3];
        
        // error checking
        if(check_session(session, sequence, username)){
            close(sock);
            return;
        }
        
        if(pathname.empty() || pathname[0] != '/' || pathname[pathname.size()-1] == '/'){
            close(sock);
            return;
        }
        std::vector<std::string> dirs = split(pathname, '/');
        
        std::string dir = dirs[dirs.size()-1];//pop the last
        dirs.pop_back();//one out
        
        //try to find parent
        if(dirs.size() == 0){
            lock_map[0]->writerStart();//if root is the parent, get the W lock.
        }
        else{
            lock_map[0]->readerStart();
        }
        
        fs_inode inode;//parent
        disk_readblock(0, &inode);
        //--------------remember the parent block and direntry block to write back.
        unsigned int inode_block_num = 0;
        unsigned int dir_block_num = 0;
        unsigned int dir_block_index = 0;
        //--------------
        if(!dfs(inode, dirs, 0, inode_block_num, false)){//find the parent inode
            close(sock);
            return;
        }
        
        //the second last one must be an directory
        if(inode.type == 'f' || avi_blocks.empty()){
            lock_map[inode_block_num]->writerFinish();//release the W lock of the parent first.
            close(sock);
            return;
        }
        
        fs_direntry *di;
        unsigned int di_inode_block; //child inode_block to be free
        std::vector<unsigned int> file_blocks;//if user wants to delete a file, put blocks holding that file into this vector, free later
        fs_direntry dir_entries[FS_DIRENTRIES];
        bool found = false;
        for(int i = 0;i < inode.size;i++){
            disk_readblock(inode.blocks[i], dir_entries);
            for(int j = 0;j < FS_DIRENTRIES;j++){
                if(dir_entries[j].inode_block && dir_entries[j].name == dir){
                    //find the one to delete
                    found = true;
                    dir_block_num = inode.blocks[i];
                    dir_block_index = i;
                    di = &dir_entries[j];
                    di_inode_block = di->inode_block;
                    lock_map[di_inode_block]->writerStart();//grab the W lock the the child
                    fs_inode child_inode;//parent
                    disk_readblock(di_inode_block, &child_inode);
                    //check if owner and username match
                    if(strcmp(child_inode.owner, username.c_str())){
                        lock_map[di_inode_block]->writerFinish();
                        close(sock);
                        return;
                    }
                    
                    if(child_inode.type == 'f'){
                        for(int i = 0; i < child_inode.size; i++)   file_blocks.push_back(child_inode.blocks[i]);
                    }
                    else{
                        if(child_inode.size){
                            close(sock);
                            return;
                        }
                    }
                    break;
                }
            }
            if(found)   break;
        }
        
        if(!found){
            lock_map[inode_block_num]->writerFinish();//release the W lock of the parent first.
            close(sock);
            return;
        }
        
        // check if need to delete direntry block
        di->inode_block = 0;
        bool need_to_delete_direntry_block = true;
        for(int i = 0; i < FS_DIRENTRIES; i++){
            if(dir_entries[i].inode_block){
                need_to_delete_direntry_block = false;
                break;
            }
        }
        
        if(need_to_delete_direntry_block){
            file_blocks.push_back(dir_block_num);
            for(int i = dir_block_index; i < inode.size-1; i++){
                inode.blocks[i] = inode.blocks[i+1];
            }
            inode.size--;
            disk_writeblock(inode_block_num, &inode);
        }
        
        else{
            disk_writeblock(dir_block_num, dir_entries);
        }
        
        lock_map[di_inode_block]->writerFinish();//release W lock of child
        delete lock_map[di_inode_block];//free memory for the lock
        lock_map.erase(di_inode_block);
        lock_map[inode_block_num]->writerFinish();//release the W lock of the parent
        
        //free blocks
        avi_blocks.push(di_inode_block);
        for(auto i : file_blocks)   avi_blocks.push(i);
        
        // response to client
        send_data(sock, session, sequence, pword);
        close(sock);
        
    }
    else{
        close(sock);
    }
    
}


int main(int argc, char** argv){
    //    for(int i = 0; i < argc ;i++)
    //        std::cout << argv[i] << std::endl;
    
    //read in username and password
    //    for(std::string line; std::getline(std::cin, line);){
    //        std::istringstream buf(line);
    //        std::istream_iterator<std::string> beg(buf), end;
    //        std::vector<std::string> tokens(beg, end);
    //        password_map[tokens[0]] = tokens[1];
    //    }
    //    if(argc == 2){ // port number specified
    //        int port_num = atoi(argv[1]);
    //        fs_init(port_num);
    //    }
    //    else{
    //        // port number not specified, should be assigned by OS
    //        fs_init(0);
    //    }
    
    if(argc == 4){ // port number specified
        int port_num = atoi(argv[1]);
        std::string filename(argv[3]);
        std::ifstream in(filename);
        for(std::string line; std::getline(in, line);){
            std::istringstream buf(line);
            std::istream_iterator<std::string> beg(buf), end;
            std::vector<std::string> tokens(beg, end);
            password_map[tokens[0]] = tokens[1];
            //std::cout << tokens[0] <<" " << tokens[1] << std::endl;
        }
        fs_init(port_num);
    }
    else{
        // port number not specified, should be assigned by OS
        fs_init(0);
    }
    
    return 0;
}


