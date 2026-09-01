//! A bounded single-use nonce window: the replay defence for control frames
//! that arrive with a nonce (adoption tickets, local control, signal-session
//! handshakes). Fixed capacity, no heap; the oldest entry is evicted.

/// Remembers the last `N` nonces seen.
#[derive(Debug, Clone)]
pub struct NonceWindow<const N: usize> {
    seen: [[u8; 32]; N],
    len: usize,
    next: usize,
}

impl<const N: usize> Default for NonceWindow<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NonceWindow<N> {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        NonceWindow {
            seen: [[0u8; 32]; N],
            len: 0,
            next: 0,
        }
    }

    /// True when `nonce` has been seen and is still in the window.
    #[must_use]
    pub fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.seen[..self.len].iter().any(|n| n == nonce)
    }

    /// Record `nonce`. Returns `false` (and records nothing) when it was
    /// already seen — the caller must reject the frame.
    pub fn check_and_insert(&mut self, nonce: &[u8; 32]) -> bool {
        if N == 0 || self.contains(nonce) {
            return false;
        }
        self.seen[self.next] = *nonce;
        self.next = (self.next + 1) % N;
        if self.len < N {
            self.len += 1;
        }
        true
    }

    /// Entries held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when nothing has been seen.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_is_rejected_until_evicted() {
        let mut w = NonceWindow::<3>::new();
        let n = |b: u8| [b; 32];
        assert!(w.check_and_insert(&n(1)));
        assert!(!w.check_and_insert(&n(1)));
        assert!(w.check_and_insert(&n(2)));
        assert!(w.check_and_insert(&n(3)));
        assert_eq!(w.len(), 3);
        assert!(w.check_and_insert(&n(4)), "evicts the oldest");
        assert!(w.check_and_insert(&n(1)), "evicted nonce is accepted again");
        assert!(!w.check_and_insert(&n(4)));
        w.clear();
        assert!(w.is_empty());
        assert!(w.check_and_insert(&n(4)));
    }
}
