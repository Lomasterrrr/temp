/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 *
*/

#ifndef NESCA_THREAD_H
#define NESCA_THREAD_H

#include <condition_variable>
#include <functional>
#include <future>
#include <queue>
#include <mutex>
#include <thread>
#include <vector>

class thread_pool {
public:
  explicit thread_pool(size_t numthreads);

  template <class F, class... Args>
  auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>
  {
    using return_type = typename std::result_of<F(Args...)>::type;
    auto task = std::make_shared<std::packaged_task<return_type()>>(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
    std::future<return_type> result = task->get_future();
    {
      std::unique_lock<std::mutex> lock(queuemutex);
      if (stop){throw std::runtime_error("enqueue on stopped threadpool");}
      tasks.emplace([task]() { (*task)(); });
    }
    condition.notify_one();
    return result;
  }

  ~thread_pool();

private:
  std::vector<std::thread> workers;
  std::queue<std::function<void()>> tasks;

  std::mutex queuemutex;
  std::condition_variable condition;

  bool stop;
};

#endif

