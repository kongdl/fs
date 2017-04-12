#include "rw_lock.h"

void rwlock::readerStart(){
    std::unique_lock<std::mutex> lck (lock);
    while(numWriters > 0){
        waitingReaders.wait(lck);
    }
    numReaders++;
}

void rwlock::writerStart(){
    std::unique_lock<std::mutex> lck (lock);
    while(numReaders+numWriters > 0){
        waitingWriters.wait(lck);
    }
    numWriters++;
}

void rwlock::readerFinish(){
    std::unique_lock<std::mutex> lck (lock);
    numReaders--;
    waitingWriters.notify_one();
}

void rwlock::writerFinish(){
    std::unique_lock<std::mutex> lck (lock);
    numWriters--;
    waitingReaders.notify_all();
    waitingWriters.notify_one();
}
