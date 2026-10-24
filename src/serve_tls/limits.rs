//! The protocol limits a gRPC listener enforces on every connection (ADR-1006).
//!
//! **CHART VALUES, NOT CONSTANTS.** Max ruled on 2026-10-24 that the stream,
//! keepalive and header-list bounds (and connection age, see below) are values an operator can
//! change, with stated defaults, rather than constants marked as exceptions.
//! Adopters size clusters differently, so a limit belongs where an operator can
//! change it.
//!
//! **NO DEFAULT LIVES HERE** (ADR-0569, ADR-0705). The defaults are in each
//! module chart's `values.yaml`, which renders them into the environment; this
//! crate reads them and refuses to boot when one is absent, naming the variable
//! and the chart value. What this crate DOES own is the RANGE each value must
//! sit in: a contract bound, not configuration, so a chart can render-check
//! against the same numbers.
//!
//! | variable | chart value (under the block the caller names) | ADR-1006 default |
//! | --- | --- | --- |
//! | `LISTEN_MAX_CONCURRENT_STREAMS` | `maxConcurrentStreams` | 256 |
//! | `LISTEN_KEEPALIVE_INTERVAL_SECS` | `keepaliveIntervalSeconds` | 30 |
//! | `LISTEN_KEEPALIVE_TIMEOUT_SECS` | `keepaliveTimeoutSeconds` | 10 |
//! | `LISTEN_MAX_HEADER_LIST_BYTES` | `maxHeaderListBytes` | 16384 |
//!
//! **NO CONNECTION AGE YET, although ADR-1006 rules a 30 min one.** On tonic
//! 0.14.6, `Server::max_connection_age` panics the connection task ("async fn
//! resumed after completion") right after it sends GOAWAY, so calls in flight on
//! that connection fail with BrokenPipe instead of finishing. tonic does NOT wait
//! for in-flight streams there, and `max_connection_age_grace` does not help. The
//! upstream fix, tonic#2780, is unreleased. The setter and its key
//! (`LISTEN_MAX_CONNECTION_AGE_SECS`) come back with the tonic release that
//! carries the fix: yaadgaar #417.
//!
//! **No `tcp_keepalive`, no server `timeout`.** ADR-1006 ruled on neither. A server `timeout` in
//! particular would cut calls short under the caller's own deadline and break
//! the inward-shrinking timeout chain the same ADR sets.

use std::ops::RangeInclusive;
use std::time::Duration;

use tonic::transport::Server;

/// The listener's protocol limits, read once at boot and applied to every
/// server [`super::server`] builds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    max_concurrent_streams: u32,
    keepalive_interval: Duration,
    keepalive_timeout: Duration,
    max_header_list_bytes: u32,
}

/// Why the listener's limits refused to boot. Every arm names the variable and
/// the chart value.
#[derive(Debug, thiserror::Error)]
pub enum ServerLimitsError {
    #[error(
        "{var} is not set. Set the chart value `{chart}`; an absent limit refuses to boot \
         rather than taking a value nobody wrote (ADR-1006, ADR-0569)"
    )]
    Missing { var: String, chart: String },

    #[error("{var} is {value:?}, which is not a whole number. Set the chart value `{chart}`")]
    NotANumber {
        var: String,
        chart: String,
        value: String,
    },

    #[error(
        "{var} is {value}, outside {min}..={max}. Set the chart value `{chart}` inside that \
         range (ADR-1006)"
    )]
    OutOfRange {
        var: String,
        chart: String,
        value: u64,
        min: u64,
        max: u64,
    },

    #[error(
        "{timeout_var} ({timeout}s) is not below {interval_var} ({interval}s): the next \
         keepalive PING would be sent before the last one could be judged lost. Lower \
         `{chart}.keepaliveTimeoutSeconds` or raise `{chart}.keepaliveIntervalSeconds`"
    )]
    KeepaliveTimeoutNotBelowInterval {
        timeout_var: String,
        interval_var: String,
        chart: String,
        timeout: u64,
        interval: u64,
    },
}

impl ServerLimits {
    /// The legal range of `maxConcurrentStreams`, per connection.
    pub const MAX_CONCURRENT_STREAMS: RangeInclusive<u64> = 1..=10_000;
    /// The legal range of `keepaliveIntervalSeconds`.
    pub const KEEPALIVE_INTERVAL_SECS: RangeInclusive<u64> = 1..=3_600;
    /// The legal range of `keepaliveTimeoutSeconds`; it must also sit below
    /// the interval.
    pub const KEEPALIVE_TIMEOUT_SECS: RangeInclusive<u64> = 1..=600;
    /// The legal range of `maxHeaderListBytes`: 1 KiB to 1 MiB.
    pub const MAX_HEADER_LIST_BYTES: RangeInclusive<u64> = 1_024..=1_048_576;

    /// [`Self::from_lookup`] over the process environment.
    pub fn from_env(prefix: &str, chart_key: &str) -> Result<Self, ServerLimitsError> {
        Self::from_lookup(prefix, chart_key, |key| std::env::var(key).ok())
    }

    /// Read the limits through `lookup`: `{prefix}_<NAME>` variables, refused
    /// with `{chart_key}.<leaf>` named. Every key is required.
    pub fn from_lookup(
        prefix: &str,
        chart_key: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ServerLimitsError> {
        let read = |name: &str, leaf: &str, range: RangeInclusive<u64>| {
            read_one(
                &lookup,
                &format!("{prefix}_{name}"),
                &format!("{chart_key}.{leaf}"),
                range,
            )
        };
        let streams = read(
            "MAX_CONCURRENT_STREAMS",
            "maxConcurrentStreams",
            Self::MAX_CONCURRENT_STREAMS,
        )?;
        let interval = read(
            "KEEPALIVE_INTERVAL_SECS",
            "keepaliveIntervalSeconds",
            Self::KEEPALIVE_INTERVAL_SECS,
        )?;
        let timeout = read(
            "KEEPALIVE_TIMEOUT_SECS",
            "keepaliveTimeoutSeconds",
            Self::KEEPALIVE_TIMEOUT_SECS,
        )?;
        let header = read(
            "MAX_HEADER_LIST_BYTES",
            "maxHeaderListBytes",
            Self::MAX_HEADER_LIST_BYTES,
        )?;
        if timeout >= interval {
            return Err(ServerLimitsError::KeepaliveTimeoutNotBelowInterval {
                timeout_var: format!("{prefix}_KEEPALIVE_TIMEOUT_SECS"),
                interval_var: format!("{prefix}_KEEPALIVE_INTERVAL_SECS"),
                chart: chart_key.to_string(),
                timeout,
                interval,
            });
        }
        Ok(Self {
            max_concurrent_streams: narrow(streams),
            keepalive_interval: Duration::from_secs(interval),
            keepalive_timeout: Duration::from_secs(timeout),
            max_header_list_bytes: narrow(header),
        })
    }

    /// The most concurrent streams one connection may open.
    pub fn max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams
    }

    /// How often an idle connection is PINGed.
    pub fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    /// How long a PING may go unanswered before the connection is closed.
    pub fn keepalive_timeout(&self) -> Duration {
        self.keepalive_timeout
    }

    /// The largest header list, in bytes, a request may carry.
    pub fn max_header_list_bytes(&self) -> u32 {
        self.max_header_list_bytes
    }

    /// Apply every limit to `server`. The ONE place a limit is set, so the TLS
    /// and cleartext builders cannot diverge.
    pub(super) fn apply(&self, server: Server) -> Server {
        server
            .max_concurrent_streams(self.max_concurrent_streams)
            .http2_keepalive_interval(Some(self.keepalive_interval))
            .http2_keepalive_timeout(Some(self.keepalive_timeout))
            // NO `.max_connection_age(..)`: it breaks in-flight calls on tonic
            // 0.14.6 (see the module docs, yaadgaar #417).
            .http2_max_header_list_size(self.max_header_list_bytes)
    }
}

fn read_one(
    lookup: &impl Fn(&str) -> Option<String>,
    var: &str,
    chart: &str,
    range: RangeInclusive<u64>,
) -> Result<u64, ServerLimitsError> {
    let Some(raw) = lookup(var)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        return Err(ServerLimitsError::Missing {
            var: var.to_string(),
            chart: chart.to_string(),
        });
    };
    let value: u64 = raw.parse().map_err(|_| ServerLimitsError::NotANumber {
        var: var.to_string(),
        chart: chart.to_string(),
        value: raw.clone(),
    })?;
    if !range.contains(&value) {
        return Err(ServerLimitsError::OutOfRange {
            var: var.to_string(),
            chart: chart.to_string(),
            value,
            min: *range.start(),
            max: *range.end(),
        });
    }
    Ok(value)
}

/// Both u32-typed ranges end far below `u32::MAX`, so a range-checked value
/// always fits.
fn narrow(value: u64) -> u32 {
    u32::try_from(value).expect("every u32-typed limit's range ends below u32::MAX")
}
