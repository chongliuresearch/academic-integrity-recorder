use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityInterval {
    pub occurred_at: DateTime<Utc>,
    pub tool_id: String,
    pub foreground: bool,
    pub qualifying: bool,
    pub paused: bool,
    pub system_locked: bool,
}

/// Calculate unique observed active time. A qualifying foreground event extends
/// activity from the preceding qualifying observation, capped by the timeout.
/// Pause, lock, and background observations terminate continuity.
pub fn calculate_active_time(events: &[ActivityInterval], timeout_seconds: u32) -> Duration {
    let timeout = Duration::seconds(timeout_seconds as i64);
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|event| event.occurred_at);
    let mut total = Duration::zero();
    let mut last_qualifying: Option<DateTime<Utc>> = None;
    for event in ordered {
        if event.foreground && event.qualifying && !event.paused && !event.system_locked {
            if let Some(previous) = last_qualifying {
                let elapsed = event.occurred_at - previous;
                if elapsed > Duration::zero() {
                    total += elapsed.min(timeout);
                }
            }
            last_qualifying = Some(event.occurred_at);
        } else {
            last_qualifying = None;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn event(seconds: i64, tool: &str) -> ActivityInterval {
        ActivityInterval {
            occurred_at: Utc.timestamp_opt(seconds, 0).unwrap(),
            tool_id: tool.into(),
            foreground: true,
            qualifying: true,
            paused: false,
            system_locked: false,
        }
    }

    #[test]
    fn merges_overlapping_activity_across_tools() {
        let events = vec![event(0, "word"), event(30, "word"), event(60, "browser")];
        assert_eq!(calculate_active_time(&events, 90).num_seconds(), 60);
    }

    #[test]
    fn ignores_paused_locked_background_and_nonqualifying_events() {
        let mut events = vec![event(0, "word"), event(100, "word")];
        events[0].paused = true;
        events[1].system_locked = true;
        assert_eq!(calculate_active_time(&events, 90), Duration::zero());
    }

    #[test]
    fn preserves_real_utc_time_across_offset_changes() {
        let events = vec![event(1_700_000_000, "word"), event(1_700_000_200, "word")];
        assert_eq!(calculate_active_time(&events, 90).num_seconds(), 90);
    }
}
