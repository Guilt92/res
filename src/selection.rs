//! Upstream selection strategies.
//!
//! # Scoring
//!
//! Selection never crosses priority tiers: candidates are grouped by
//! `priority` (lower is better) and only the best non-empty tier is
//! considered. Inside a tier each candidate gets a score:
//!
//! ```text
//! health_factor   = 1.0 if UP, 0.4 if DEGRADED
//! reliability     = (successes + 1) / (samples + 2)        // Laplace smoothed,
//!                                                           // rolling window
//! latency_factor  = ref / (ref + p95_ms)                   // ref = 50ms default
//! score           = health_factor * reliability * latency_factor * weight
//! ```
//!
//! Reliability dominates deliberately: an upstream with 5 ms latency and a 20%
//! failure rate must not win over one with 12 ms latency and ~0% failures.
//! Latency only breaks ties between similarly reliable upstreams, and `weight`
//! sets the long-run traffic share inside a tier.
//!
//! Strategies are replaceable behind [`UpstreamSelector`].

use std::sync::Arc;

use crate::upstream::{HealthStatus, UpstreamRuntime, ViewInputs};

/// Immutable per-candidate view handed to selectors (allocation free, easy to
/// unit test).
#[derive(Debug, Clone, Copy)]
pub struct StateView {
    pub id: i64,
    pub health: HealthStatus,
    pub priority: u32,
    pub weight: u32,
    /// Laplace-smoothed success rate over the rolling outcome window.
    pub reliability: f64,
    pub p95_ms: f64,
    pub avg_ms: f64,
    pub has_latency: bool,
}

impl StateView {
    pub fn from_runtime(rt: &UpstreamRuntime) -> Self {
        let v: ViewInputs = rt.view_inputs();
        Self {
            id: rt.id(),
            health: v.status,
            priority: v.priority,
            weight: v.weight,
            reliability: v.reliability,
            p95_ms: v.p95_ms,
            avg_ms: v.avg_ms,
            has_latency: v.has_latency,
        }
    }

    /// Composite score for this candidate (see module docs).
    pub fn score(&self, latency_reference_ms: f64) -> f64 {
        let health_factor = match self.health {
            HealthStatus::Up => 1.0,
            HealthStatus::Degraded => 0.4,
            HealthStatus::Down => 0.0,
        };
        let latency = if self.has_latency {
            self.p95_ms.max(self.avg_ms)
        } else {
            // No data yet: neutral latency (scores 0.5 on the latency term).
            latency_reference_ms
        };
        let latency_factor = latency_reference_ms / (latency_reference_ms + latency);
        health_factor * self.reliability * latency_factor * self.weight as f64
    }
}

/// Pluggable selection strategy.
pub trait UpstreamSelector: Send + Sync {
    /// Pick one candidate id from the supplied usable candidates.
    fn select(&self, candidates: &[StateView]) -> Option<i64>;
    /// Human readable strategy name (status endpoint).
    fn describe(&self) -> &'static str;
}

/// Sized wrapper around a trait-object selector so it can be stored in an
/// [`arc_swap::ArcSwap`] (arc-swap requires `Sized` for its `RefCnt` impl).
#[derive(Clone)]
pub struct SelectorHandle(pub Arc<dyn UpstreamSelector>);

impl SelectorHandle {
    pub fn new(selector: Arc<dyn UpstreamSelector>) -> Self {
        Self(selector)
    }
}

impl std::ops::Deref for SelectorHandle {
    type Target = dyn UpstreamSelector;
    fn deref(&self) -> &(dyn UpstreamSelector + 'static) {
        self.0.as_ref()
    }
}

/// Keep only usable candidates (UP / DEGRADED) and restrict them to the best
/// (lowest) priority tier present.
fn usable_tier(candidates: &[StateView]) -> Vec<StateView> {
    let usable: Vec<StateView> = candidates
        .iter()
        .copied()
        .filter(|c| c.health.is_usable())
        .collect();
    let Some(best) = usable.iter().map(|c| c.priority).min() else {
        return Vec::new();
    };
    usable.into_iter().filter(|c| c.priority == best).collect()
}

/// Default strategy: weighted roulette over the composite score.
pub struct WeightedReliabilitySelector {
    pub latency_reference_ms: f64,
}

impl UpstreamSelector for WeightedReliabilitySelector {
    fn select(&self, candidates: &[StateView]) -> Option<i64> {
        let tier = usable_tier(candidates);
        if tier.is_empty() {
            return None;
        }
        let scores: Vec<f64> = tier
            .iter()
            .map(|c| c.score(self.latency_reference_ms))
            .collect();
        let total: f64 = scores.iter().sum();
        if total <= 0.0 {
            return Some(tier[0].id);
        }
        let mut roll = fastrand::f64() * total;
        for (c, s) in tier.iter().zip(scores) {
            roll -= s;
            if roll < 0.0 {
                return Some(c.id);
            }
        }
        Some(tier.last().expect("non-empty tier").id)
    }

    fn describe(&self) -> &'static str {
        "weighted_reliability"
    }
}

/// Deterministic strategy: always the highest scoring candidate.
pub struct BestScoreSelector {
    pub latency_reference_ms: f64,
}

impl UpstreamSelector for BestScoreSelector {
    fn select(&self, candidates: &[StateView]) -> Option<i64> {
        let tier = usable_tier(candidates);
        if tier.is_empty() {
            return None;
        }
        let mut best: Option<(i64, f64)> = None;
        for c in &tier {
            let s = c.score(self.latency_reference_ms);
            match best {
                Some((id, bs)) if !(s > bs || (s == bs && c.id < id)) => {}
                _ => best = Some((c.id, s)),
            }
        }
        best.map(|(id, _)| id)
    }

    fn describe(&self) -> &'static str {
        "best_score"
    }
}

/// Uniform random choice among the best-priority usable candidates.
pub struct RandomHealthySelector;

impl UpstreamSelector for RandomHealthySelector {
    fn select(&self, candidates: &[StateView]) -> Option<i64> {
        let tier = usable_tier(candidates);
        if tier.is_empty() {
            return None;
        }
        let idx = fastrand::usize(0..tier.len());
        Some(tier[idx].id)
    }

    fn describe(&self) -> &'static str {
        "random_healthy"
    }
}

/// Build the configured selector.
pub fn build_selector(cfg: &crate::config::SelectionConfig) -> Box<dyn UpstreamSelector> {
    use crate::config::SelectionStrategy;
    match cfg.strategy {
        SelectionStrategy::WeightedReliability => Box::new(WeightedReliabilitySelector {
            latency_reference_ms: cfg.latency_reference_ms,
        }),
        SelectionStrategy::BestScore => Box::new(BestScoreSelector {
            latency_reference_ms: cfg.latency_reference_ms,
        }),
        SelectionStrategy::RandomHealthy => Box::new(RandomHealthySelector),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(
        id: i64,
        health: HealthStatus,
        priority: u32,
        weight: u32,
        rel: f64,
        p95: f64,
    ) -> StateView {
        StateView {
            id,
            health,
            priority,
            weight,
            reliability: rel,
            p95_ms: p95,
            avg_ms: p95,
            has_latency: p95 > 0.0,
        }
    }

    #[test]
    fn down_upstreams_are_never_selected() {
        let sel = WeightedReliabilitySelector {
            latency_reference_ms: 50.0,
        };
        let cands = vec![
            view(1, HealthStatus::Down, 1, 1, 0.9, 5.0),
            view(2, HealthStatus::Up, 1, 1, 0.9, 5.0),
        ];
        for _ in 0..50 {
            assert_eq!(sel.select(&cands), Some(2));
        }
        let all_down = vec![view(1, HealthStatus::Down, 1, 1, 0.9, 5.0)];
        assert_eq!(sel.select(&all_down), None);
    }

    #[test]
    fn priority_tier_wins_over_score() {
        let sel = BestScoreSelector {
            latency_reference_ms: 50.0,
        };
        // Tier 1 is degraded and slow; tier 2 is perfect. Tier 1 must win.
        let cands = vec![
            view(1, HealthStatus::Degraded, 2, 1, 1.0, 1.0),
            view(2, HealthStatus::Up, 1, 1, 0.5, 100.0),
        ];
        assert_eq!(sel.select(&cands), Some(2));
    }

    #[test]
    fn reliability_beats_latency() {
        // A: 5 ms but 60% reliable. B: 12 ms but ~100% reliable.
        let a = view(1, HealthStatus::Up, 1, 1, 0.6, 5.0);
        let b = view(2, HealthStatus::Up, 1, 1, 0.99, 12.0);
        let score_ref = 50.0;
        assert!(b.score(score_ref) > a.score(score_ref));
    }

    #[test]
    fn degraded_is_penalised_but_usable() {
        let up = view(1, HealthStatus::Up, 1, 1, 0.9, 10.0);
        let deg = view(2, HealthStatus::Degraded, 1, 1, 0.9, 10.0);
        assert!(up.score(50.0) > deg.score(50.0));
        let sel = WeightedReliabilitySelector {
            latency_reference_ms: 50.0,
        };
        // Degraded is still a valid fallback when it is alone.
        assert_eq!(sel.select(&[deg]), Some(2));
    }

    #[test]
    fn weight_influences_distribution() {
        fastrand::seed(42);
        let sel = WeightedReliabilitySelector {
            latency_reference_ms: 50.0,
        };
        let cands = vec![
            view(1, HealthStatus::Up, 1, 1, 1.0, 10.0),
            view(2, HealthStatus::Up, 1, 9, 1.0, 10.0),
        ];
        let mut wins = [0u32; 2];
        for _ in 0..2000 {
            let pick = sel.select(&cands).unwrap();
            wins[if pick == 1 { 0 } else { 1 }] += 1;
        }
        // Equal scores except weight 1 vs 9 -> roughly 10% / 90%.
        assert!(wins[0] > 100, "weight-1 upstream got too many: {wins:?}");
        assert!(wins[0] < 400, "weight-1 upstream got too many: {wins:?}");
    }

    #[test]
    fn weighted_distribution_is_stochastic_not_just_argmax() {
        fastrand::seed(7);
        let sel = WeightedReliabilitySelector {
            latency_reference_ms: 50.0,
        };
        let cands = vec![
            view(1, HealthStatus::Up, 1, 1, 1.0, 10.0),
            view(2, HealthStatus::Up, 1, 1, 1.0, 10.0),
        ];
        let mut wins = [0u32; 2];
        for _ in 0..1000 {
            let pick = sel.select(&cands).unwrap();
            wins[if pick == 1 { 0 } else { 1 }] += 1;
        }
        assert!(wins[0] > 350 && wins[0] < 650, "not ~50/50: {wins:?}");
    }

    #[test]
    fn no_latency_is_neutral() {
        let fresh = view(1, HealthStatus::Up, 1, 1, 0.9, 0.0);
        assert!(!fresh.has_latency);
        let s = fresh.score(50.0);
        // reliability * 0.5 * weight
        assert!((s - 0.9 * 0.5).abs() < 1e-9, "{s}");
    }

    #[test]
    fn empty_candidates_select_nothing() {
        let sel = WeightedReliabilitySelector {
            latency_reference_ms: 50.0,
        };
        assert_eq!(sel.select(&[]), None);
        assert_eq!(
            BestScoreSelector {
                latency_reference_ms: 50.0
            }
            .select(&[]),
            None
        );
        assert_eq!(RandomHealthySelector.select(&[]), None);
    }
}
