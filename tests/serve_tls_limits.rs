//! The listener's protocol limits (ADR-1006): how they are read, and what is
//! refused before anything binds.
//!
//! **EVERY KEY IS REQUIRED and none has a value in this crate** (ADR-0569,
//! ADR-0705). The chart carries the default and renders it into the
//! environment; an absent key is a boot refusal naming the variable AND the
//! chart value, so the operator reads one in a crash log and edits the other.

mod serve_tls_rig;

use std::time::Duration;

use serve_tls_rig::lookup;
use yadgar_lifecycle::serve_tls::{ServerLimits, ServerLimitsError, LISTEN};

const CHART: &str = "server.limits";

/// The ADR-1006 values, as a chart renders them.
fn adr_1006() -> Vec<(&'static str, String)> {
    vec![
        ("LISTEN_MAX_CONCURRENT_STREAMS", "256".into()),
        ("LISTEN_KEEPALIVE_INTERVAL_SECS", "30".into()),
        ("LISTEN_KEEPALIVE_TIMEOUT_SECS", "10".into()),
        ("LISTEN_MAX_HEADER_LIST_BYTES", "16384".into()),
    ]
}

fn with(key: &str, value: Option<&str>) -> Vec<(&'static str, String)> {
    let mut pairs: Vec<_> = adr_1006().into_iter().filter(|(k, _)| *k != key).collect();
    if let Some(v) = value {
        let k = adr_1006().into_iter().find(|(k, _)| *k == key).unwrap().0;
        pairs.push((k, v.to_string()));
    }
    pairs
}

fn read(pairs: &[(&str, String)]) -> Result<ServerLimits, ServerLimitsError> {
    ServerLimits::from_lookup(LISTEN, CHART, lookup(pairs))
}

fn refusal(pairs: &[(&str, String)]) -> String {
    read(pairs)
        .expect_err("this configuration must refuse to boot")
        .to_string()
}

const KEYS: [(&str, &str); 4] = [
    (
        "LISTEN_MAX_CONCURRENT_STREAMS",
        "server.limits.maxConcurrentStreams",
    ),
    (
        "LISTEN_KEEPALIVE_INTERVAL_SECS",
        "server.limits.keepaliveIntervalSeconds",
    ),
    (
        "LISTEN_KEEPALIVE_TIMEOUT_SECS",
        "server.limits.keepaliveTimeoutSeconds",
    ),
    (
        "LISTEN_MAX_HEADER_LIST_BYTES",
        "server.limits.maxHeaderListBytes",
    ),
];

#[test]
fn the_adr_1006_values_read_to_what_they_name() {
    let limits = read(&adr_1006()).expect("the ADR-1006 values are in range");
    assert_eq!(limits.max_concurrent_streams(), 256);
    assert_eq!(limits.keepalive_interval(), Duration::from_secs(30));
    assert_eq!(limits.keepalive_timeout(), Duration::from_secs(10));
    assert_eq!(limits.max_header_list_bytes(), 16 * 1024);
}

#[test]
fn an_absent_or_empty_key_refuses_naming_the_variable_and_the_chart_value() {
    for (var, chart) in KEYS {
        for value in [None, Some(""), Some("  ")] {
            let message = refusal(&with(var, value));
            assert!(message.contains(var), "{value:?}: {message}");
            assert!(message.contains(chart), "{value:?}: {message}");
        }
    }
}

#[test]
fn a_value_that_is_not_a_whole_number_refuses() {
    for (var, chart) in KEYS {
        for value in ["thirty", "-1", "1.5", "30s"] {
            let message = refusal(&with(var, Some(value)));
            assert!(message.contains(var), "{value}: {message}");
            assert!(message.contains(chart), "{value}: {message}");
            assert!(message.contains(value), "{value}: {message}");
        }
    }
}

/// Each key's lowest and highest legal value boots; one step past either end
/// refuses, naming the range.
#[test]
fn a_value_outside_its_range_refuses_naming_the_range() {
    let ranges = [
        (
            "LISTEN_MAX_CONCURRENT_STREAMS",
            ServerLimits::MAX_CONCURRENT_STREAMS,
        ),
        (
            "LISTEN_KEEPALIVE_INTERVAL_SECS",
            ServerLimits::KEEPALIVE_INTERVAL_SECS,
        ),
        (
            "LISTEN_KEEPALIVE_TIMEOUT_SECS",
            ServerLimits::KEEPALIVE_TIMEOUT_SECS,
        ),
        (
            "LISTEN_MAX_HEADER_LIST_BYTES",
            ServerLimits::MAX_HEADER_LIST_BYTES,
        ),
    ];
    for (var, range) in ranges {
        for outside in [range.start() - 1, range.end() + 1] {
            let message = refusal(&with(var, Some(&outside.to_string())));
            assert!(message.contains(var), "{outside}: {message}");
            assert!(message.contains(&range.start().to_string()), "{message}");
            assert!(message.contains(&range.end().to_string()), "{message}");
        }
    }
}

#[test]
fn every_range_admits_the_adr_1006_value() {
    assert!(ServerLimits::MAX_CONCURRENT_STREAMS.contains(&256));
    assert!(ServerLimits::KEEPALIVE_INTERVAL_SECS.contains(&30));
    assert!(ServerLimits::KEEPALIVE_TIMEOUT_SECS.contains(&10));
    assert!(ServerLimits::MAX_HEADER_LIST_BYTES.contains(&16384));
}

/// A keepalive whose timeout is not below its interval would send the next
/// PING before the last one could be judged lost.
#[test]
fn a_keepalive_timeout_not_below_its_interval_refuses() {
    for timeout in ["30", "31"] {
        let mut pairs = with("LISTEN_KEEPALIVE_TIMEOUT_SECS", Some(timeout));
        pairs.retain(|(k, _)| *k != "LISTEN_KEEPALIVE_INTERVAL_SECS");
        pairs.push(("LISTEN_KEEPALIVE_INTERVAL_SECS", "30".into()));
        let message = refusal(&pairs);
        assert!(
            message.contains("LISTEN_KEEPALIVE_TIMEOUT_SECS"),
            "{message}"
        );
        assert!(
            message.contains("LISTEN_KEEPALIVE_INTERVAL_SECS"),
            "{message}"
        );
    }
    let mut pairs = with("LISTEN_KEEPALIVE_TIMEOUT_SECS", Some("29"));
    pairs.retain(|(k, _)| *k != "LISTEN_KEEPALIVE_INTERVAL_SECS");
    pairs.push(("LISTEN_KEEPALIVE_INTERVAL_SECS", "30".into()));
    read(&pairs).expect("a timeout one second below its interval boots");
}

#[test]
fn surrounding_whitespace_is_trimmed() {
    let pairs = with("LISTEN_MAX_CONCURRENT_STREAMS", Some(" 128 \n"));
    assert_eq!(read(&pairs).unwrap().max_concurrent_streams(), 128);
}

/// THE RANGES AS LITERALS (ADR-0573). Every other case here derives its bounds
/// from the consts, so a const moved by mistake would carry those cases with
/// it; charts in six repositories render-check against these numbers.
#[test]
fn the_ranges_are_the_literals_the_charts_check_against() {
    assert_eq!(ServerLimits::MAX_CONCURRENT_STREAMS, 1..=10_000);
    assert_eq!(ServerLimits::KEEPALIVE_INTERVAL_SECS, 1..=3_600);
    assert_eq!(ServerLimits::KEEPALIVE_TIMEOUT_SECS, 1..=600);
    assert_eq!(ServerLimits::MAX_HEADER_LIST_BYTES, 1_024..=1_048_576);
}

/// NO CONNECTION-AGE KEY IS READ (yaadgaar #417): tonic 0.14.6's
/// `max_connection_age` breaks in-flight calls, so the four keys above are the
/// whole configuration and a stale age key from an older chart changes nothing.
#[test]
fn a_connection_age_key_is_neither_required_nor_read() {
    let mut pairs = adr_1006();
    let without = read(&pairs).expect("four keys are the whole configuration");
    pairs.push(("LISTEN_MAX_CONNECTION_AGE_SECS", "not even a number".into()));
    assert_eq!(read(&pairs).expect("an age key is ignored"), without);
}
