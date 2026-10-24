//! Rate limits with fixed memory (SERVER.md §9).
//!
//! A count-min sketch per fixed window: it never fills up, never forgets a heavy key inside
//! its window, never refuses a *new* key for lack of room (the 4.x hello-pass table wiped
//! itself at 200k, L4), and can only over-count. Keys are a network (IPv4 address, IPv6 /64,
//! from the socket), an account, or a session.

use std::sync::Mutex;

use crate::crypto;

/// One limiter: `limit` events per `window_ms`.
pub struct Sketch {
    limit: u32,
    window_ms: i64,
    inner: Mutex<Inner>,
}

struct Inner {
    window: i64,
    rows: Vec<Vec<u32>>,
}

const ROWS: usize = 4;
const WIDTH: usize = 1 << 14;

impl Sketch {
    /// A limiter.
    #[must_use]
    pub fn new(limit: u32, window_ms: i64) -> Self {
        Self {
            limit,
            window_ms: window_ms.max(1),
            inner: Mutex::new(Inner {
                window: -1,
                rows: vec![vec![0; WIDTH]; ROWS],
            }),
        }
    }

    fn cells(key: &str) -> [usize; ROWS] {
        let h = crypto::sha3_512(key.as_bytes());
        let mut out = [0usize; ROWS];
        for (r, o) in out.iter_mut().enumerate() {
            let v = u32::from_be_bytes([h[r * 4], h[r * 4 + 1], h[r * 4 + 2], h[r * 4 + 3]]);
            *o = v as usize % WIDTH;
        }
        out
    }

    /// Count one event for `key` at `now`; false (and nothing counted) when over the limit.
    pub fn take(&self, key: &str, now: i64) -> bool {
        self.take_n(key, 1, now)
    }

    /// Count `n` events.
    pub fn take_n(&self, key: &str, n: u32, now: i64) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        let w = now.div_euclid(self.window_ms);
        if w != g.window {
            g.window = w;
            for row in &mut g.rows {
                row.iter_mut().for_each(|c| *c = 0);
            }
        }
        let cells = Self::cells(key);
        let est = cells
            .iter()
            .enumerate()
            .map(|(r, &c)| g.rows[r][c])
            .min()
            .unwrap_or(0);
        if est.saturating_add(n) > self.limit {
            return false;
        }
        for (r, &c) in cells.iter().enumerate() {
            g.rows[r][c] = g.rows[r][c].saturating_add(n);
        }
        true
    }

    /// The current estimate for `key`.
    pub fn peek(&self, key: &str, now: i64) -> u32 {
        let Ok(g) = self.inner.lock() else {
            return u32::MAX;
        };
        if now.div_euclid(self.window_ms) != g.window {
            return 0;
        }
        Self::cells(key)
            .iter()
            .enumerate()
            .map(|(r, &c)| g.rows[r][c])
            .min()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_windows() {
        let s = Sketch::new(3, 1000);
        assert!(s.take("a", 0) && s.take("a", 1) && s.take("a", 2));
        assert!(!s.take("a", 3), "fourth in the window refused");
        assert!(s.take("b", 3), "another key is unaffected");
        assert!(s.take("a", 1000), "a new window starts fresh");
    }

    #[test]
    fn never_locks_out_new_keys() {
        // 50,000 networks each make one handshake in a minute (limit 30 each). Each cell then
        // holds about 3; a new network is never refused for lack of room, only if its cells
        // were all pushed to 30 by others.
        let s = Sketch::new(30, 60_000);
        for i in 0..50_000 {
            s.take(&format!("flood-{i}"), 0);
        }
        let ok = (0..1000).filter(|i| s.take(&format!("new-{i}"), 0)).count();
        assert_eq!(ok, 1000);
    }
}
