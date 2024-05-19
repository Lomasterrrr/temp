/*
 *          NESCA4
 *   Сделано от души 2024.
 * Copyright (c) [2024] [lomaster]
 * SPDX-License-Identifier: BSD-3-Clause
 *
*/

#include "../include/nescathread.h"

thread_pool::thread_pool(size_t numthreads) : stop(false)
{
  size_t i;
  for (i = 0; i < numthreads; ++i) {
    workers.emplace_back([this] {
      while (true) {
        std::function<void()> task; {
          std::unique_lock<std::mutex> lock(queuemutex);
          condition.wait(lock, [this] { return stop || !tasks.empty(); });
          if (stop && tasks.empty()) {return;}
            task = std::move(tasks.front());
            tasks.pop();
          }
          task();
        }
      }
    );
  }
}

thread_pool::~thread_pool()
{
  {
    std::unique_lock<std::mutex> lock(queuemutex);
    stop = true;
  }

  condition.notify_all();
  for (std::thread& worker : workers){worker.join();}
}
