//! The protocol limits a gRPC listener enforces on every connection (ADR-1006).
//!
//! **CHART VALUES, NOT CONSTANTS.** Max ruled on 2026-10-24 that the stream,
//! keepalive, header-list and connection-age bounds are values an operator can
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
//! | `LISTEN_MAX_CONNECTION_AGE_SECS` | `maxConnectionAgeSeconds` | 1800 |
//!
//! **THE CONNECTION AGE NEEDS tonic 0.14.7 OR LATER, and `Cargo.toml` floors
//! tonic there.** On tonic 0.14.6, `Server::max_connection_age` panicked the
//! connection task ("async fn resumed after completion") right after it sent
//! GOAWAY, so calls in flight on that connection failed with BrokenPipe. tonic
//! 0.14.7 wraps the age timer in a `Fuse` (tonic#2780,
//! `src/transport/server/mod.rs:968`): the connection now sends GOAWAY, lets
//! the calls in flight finish, and closes (yaadgaar #290 item 2).
//!
//! **No `max_connection_age_grace`, on purpose.** In tonic 0.14.7, setting a
//! grace makes the age timer skip the graceful step entirely: it sleeps
//! age + grace and then closes the connection hard, with no GOAWAY
//! (`connection_timeout_future`, `src/transport/server/mod.rs:923-937`). That
//! drops the calls in flight, which is the failure this bound waited for tonic
//! to fix. Without a grace, a call that never ends keeps its connection open;
//! the process drain budget bounds that at shutdown.
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
    max_connection_age: Duration,
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
    /// The legal range of `maxConnectionAgeSeconds`: one second to one day.
    pub const MAX_CONNECTION_AGE_SECS: RangeInclusive<u64> = 1..=86_400;

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
        let age = read(
            "MAX_CONNECTION_AGE_SECS",
            "maxConnectionAgeSeconds",
            Self::MAX_CONNECTION_AGE_SECS,
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
            max_connection_age: Duration::from_secs(age),
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

    /// How old a connection may grow before it is sent GOAWAY. Calls in flight
    /// on it finish; new calls go to a fresh connection.
    pub fn max_connection_age(&self) -> Duration {
        self.max_connection_age
    }

    /// Apply every limit to `server`. The ONE place a limit is set, so the TLS
    /// and cleartext builders cannot diverge.
    pub(super) fn apply(&self, server: Server) -> Server {
        server
            .max_concurrent_streams(self.max_concurrent_streams)
            .http2_keepalive_interval(Some(self.keepalive_interval))
            .http2_keepalive_timeout(Some(self.keepalive_timeout))
            .http2_max_header_list_size(self.max_header_list_bytes)
            // NO `.max_connection_age_grace(..)`: it turns the GOAWAY into a
            // hard close (see the module docs).
            .max_connection_age(self.max_connection_age)
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
