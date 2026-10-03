//! A bounded FIFO of job ids with blocking pop, for the worker threads. The
//! webhook handler only ever pushes; it never runs a job.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, PoisonError};

use crate::request::JobId;

/// Why a push failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// The queue is at capacity (backpressure).
    Full,
    /// The queue is closed (shutdown).
    Closed,
}

struct Inner {
    items: VecDeque<JobId>,
    closed: bool,
}

/// The queue.
pub struct JobQueue {
    capacity: usize,
    inner: Mutex<Inner>,
    ready: Condvar,
}

impl JobQueue {
    /// A queue holding at most `capacity` pending jobs.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner {
                items: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    /// Enqueue without blocking.
    pub fn try_push(&self, id: JobId) -> Result<(), PushError> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if g.closed {
            return Err(PushError::Closed);
        }
        if g.items.len() >= self.capacity {
            return Err(PushError::Full);
        }
        g.items.push_back(id);
        drop(g);
        self.ready.notify_one();
        Ok(())
    }

    /// Wait for the next job; `None` once the queue is closed and drained of
    /// nothing a worker should still run (closing discards pending jobs).
    pub fn pop_blocking(&self) -> Option<JobId> {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if g.closed {
                return None;
            }
            if let Some(id) = g.items.pop_front() {
                return Some(id);
            }
            g = self.ready.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Pending jobs.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .len()
    }

    /// Whether nothing is pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Close: pending jobs are discarded (state is in memory and not durable)
    /// and every blocked worker returns.
    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        g.closed = true;
        g.items.clear();
        drop(g);
        self.ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> JobId {
        JobId::parse(&format!("{n:02x}").repeat(32)).unwrap()
    }

    #[test]
    fn the_queue_is_bounded_fifo_and_closes() {
        let q = JobQueue::new(2);
        assert_eq!(q.try_push(id(1)), Ok(()));
        assert_eq!(q.try_push(id(2)), Ok(()));
        assert_eq!(q.try_push(id(3)), Err(PushError::Full));
        assert_eq!(q.pop_blocking(), Some(id(1)));
        assert_eq!(q.try_push(id(3)), Ok(()));
        assert_eq!(q.len(), 2);
        q.close();
        assert_eq!(q.pop_blocking(), None);
        assert_eq!(q.try_push(id(4)), Err(PushError::Closed));
        assert!(q.is_empty());
    }
}
