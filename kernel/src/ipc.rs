//! Inter-process communication primitives (Alpha: "Basic IPC") — fixed-count
//! byte channels addressed by small integer port ids. `send`/`recv` block by
//! spin-yielding through the cooperative scheduler rather than blocking a
//! CPU outright; a real wait/wake queue (so a blocked thread isn't burning
//! its turn just to check "still empty?") is a later refinement once the
//! scheduler is timer-preemptive.

use alloc::collections::VecDeque;
use lazy_static::lazy_static;
use spin::Mutex;

const PORT_COUNT: usize = 16;
const CHANNEL_CAPACITY: usize = 32;

struct Channel {
    queue: VecDeque<u8>,
}

lazy_static! {
    static ref CHANNELS: [Mutex<Channel>; PORT_COUNT] =
        core::array::from_fn(|_| Mutex::new(Channel {
            queue: VecDeque::new()
        }));
}

/// Blocks (spin-yielding) until there's room, then enqueues `byte` on `port`.
pub fn send(port: usize, byte: u8) {
    loop {
        {
            let mut channel = CHANNELS[port].lock();
            if channel.queue.len() < CHANNEL_CAPACITY {
                channel.queue.push_back(byte);
                return;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// Non-blocking: `None` if `port` currently has nothing queued.
pub fn try_recv(port: usize) -> Option<u8> {
    CHANNELS[port].lock().queue.pop_front()
}

/// Blocks (spin-yielding) until a byte is available on `port`.
pub fn recv(port: usize) -> u8 {
    loop {
        if let Some(byte) = try_recv(port) {
            return byte;
        }
        crate::scheduler::yield_now();
    }
}
