use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TimeoutChecker {
    duration: Duration,

    start: Instant,

    counter: u32,
}

impl TimeoutChecker {
    pub fn new(duration: Duration) -> Self {
        Self {
            duration,
            start: Instant::now(),
            counter: 0,
        }
    }

    pub fn check_timeout(&mut self) -> bool {
        self.counter = self.counter.wrapping_add(1);
        self.counter % (10 * 1024) == 0 && self.start.elapsed() >= self.duration
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::test_type_traits_non_clonable;

    use super::*;

    #[test]
    fn test_types_traits() {
        test_type_traits_non_clonable(TimeoutChecker::new(Duration::from_secs(1)));
    }
}
