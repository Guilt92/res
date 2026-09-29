//! Bounded rolling latency windows.
//!
//! Windows never grow past their configured capacity, so memory usage is
//! constant regardless of query volume. Percentiles are computed on demand
//! from a bounded copy (sort of at most `capacity` samples).

use std::collections::VecDeque;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LatencyStats {
    pub count: u64,
    pub last_ms: f64,
    pub avg_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

impl LatencyStats {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Fixed-capacity rolling window of latency samples (milliseconds).
#[derive(Debug)]
pub struct LatencyWindow {
    capacity: usize,
    samples: VecDeque<f64>,
    /// Number of samples ever recorded (may exceed `capacity`).
    total: u64,
    sum: f64,
    min: f64,
    max: f64,
    last: f64,
}

impl LatencyWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            samples: VecDeque::with_capacity(capacity.max(1)),
            total: 0,
            sum: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            last: 0.0,
        }
    }

    pub fn push(&mut self, d: Duration) {
        let ms = d.as_secs_f64() * 1000.0;
        if self.samples.len() >= self.capacity {
            if let Some(old) = self.samples.pop_front() {
                self.sum -= old;
            }
        }
        self.samples.push_back(ms);
        self.sum += ms;
        self.total += 1;
        self.last = ms;
        if ms < self.min {
            self.min = ms;
        }
        if ms > self.max {
            self.max = ms;
        }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn last_ms(&self) -> f64 {
        self.last
    }

    /// Rolling statistics over the current window (not lifetime min/max).
    pub fn stats(&self) -> LatencyStats {
        if self.samples.is_empty() {
            return LatencyStats::empty();
        }
        let mut sorted: Vec<f64> = self.samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len() as f64;
        let window_min = sorted.first().copied().unwrap_or(0.0);
        let window_max = sorted.last().copied().unwrap_or(0.0);
        LatencyStats {
            count: self.total,
            last_ms: self.last,
            avg_ms: self.sum / n,
            min_ms: window_min,
            max_ms: window_max,
            p50_ms: percentile(&sorted, 50.0),
            p95_ms: percentile(&sorted, 95.0),
            p99_ms: percentile(&sorted, 99.0),
        }
    }
}

/// Nearest-rank percentile over an ascending-sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * (sorted.len() as f64 - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - lo as f64;
        sorted[lo] + (sorted[hi] - sorted[lo]) * frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn empty_window_stats_are_zero() {
        let w = LatencyWindow::new(8);
        let s = w.stats();
        assert_eq!(s.count, 0);
        assert_eq!(s.p50_ms, 0.0);
    }

    #[test]
    fn basic_stats() {
        let mut w = LatencyWindow::new(100);
        for v in [10, 20, 30, 40, 50] {
            w.push(ms(v));
        }
        let s = w.stats();
        assert_eq!(s.count, 5);
        assert_eq!(s.min_ms, 10.0);
        assert_eq!(s.max_ms, 50.0);
        assert_eq!(s.avg_ms, 30.0);
        assert_eq!(s.p50_ms, 30.0);
        assert!(s.p95_ms >= 40.0);
        assert_eq!(s.last_ms, 50.0);
    }

    #[test]
    fn window_is_bounded() {
        let mut w = LatencyWindow::new(4);
        for i in 0..1000 {
            w.push(ms(i));
        }
        assert_eq!(w.len(), 4);
        let s = w.stats();
        // Only the newest samples remain in the rolling window.
        assert_eq!(s.min_ms, 996.0);
        assert_eq!(s.max_ms, 999.0);
        assert_eq!(s.count, 1000);
    }

    #[test]
    fn percentiles_interpolate() {
        let mut w = LatencyWindow::new(10);
        for v in [1, 2, 3, 4] {
            w.push(ms(v));
        }
        let s = w.stats();
        assert!((s.p50_ms - 2.5).abs() < 1e-9, "{}", s.p50_ms);
        assert!((s.p99_ms - 3.97).abs() < 1e-9, "{}", s.p99_ms);
    }

    #[test]
    fn single_sample() {
        let mut w = LatencyWindow::new(3);
        w.push(ms(7));
        let s = w.stats();
        assert_eq!(s.p50_ms, 7.0);
        assert_eq!(s.p95_ms, 7.0);
        assert_eq!(s.p99_ms, 7.0);
    }
}
