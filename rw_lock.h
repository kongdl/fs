#ifndef rw_lock_h
#define rw_lock_h

#include <mutex>
#include <condition_variable>


class rwlock{
public:
    std::mutex lock;
    unsigned int numReaders;
    unsigned int numWriters;
    std::condition_variable waitingReaders;
    std::condition_variable waitingWriters;
    
    void readerStart();
    void readerFinish();
    void writerStart();
    void writerFinish();
    
};

#endif



