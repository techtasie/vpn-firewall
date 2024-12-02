#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <unordered_set>

#include <iostream>

template<typename T>
class UniqueThreadSafeQueue {
private:
    std::queue<T> queue_;
    std::unordered_set<T> unique_items_;  // Tracks items in queue or being processed
    std::mutex mutex_;
    std::condition_variable condition_;

public:
    // Add an item to the queue
    bool push(const T& item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (unique_items_.find(item) != unique_items_.end()) {
                return false; // Reject if the item already exists
            }
            queue_.push(item);
            unique_items_.insert(item);
        }
        condition_.notify_one(); // Notify one waiting thread
        return true;
    }

    // Retrieve and remove the front item of the queue
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] { return !queue_.empty(); }); // Wait until the queue is not empty

        T item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    // Mark an item as done
    void mark_done(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        unique_items_.erase(item);
    }

    // Check if the queue is empty
    bool empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    // Get the size of the queue
    size_t size() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};
