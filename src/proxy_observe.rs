use std::{collections::HashMap, io::BufRead};

use serde_json::{Map, Value, json};

use super::{LabResult, PROXY_EVENT_SCHEMA, ProxyMetricsSnapshot, other_error};

pub const PROXY_OBSERVATION_SCHEMA: &str = "flowweave.observe.v1";
pub const MAX_PROXY_EVENT_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyRoleObservation {
    pub runtime_started: u64,
    pub startup_failed: u64,
    pub runtime_failed: u64,
    pub credential_reloads: u64,
    pub credential_reload_failures: u64,
    pub connection_failures: u64,
    pub stream_failures: u64,
    pub timeout_events: u64,
    pub upstream_error_events: u64,
    pub connections_started: u64,
    pub connections_finished: u64,
    pub streams_started: u64,
    pub streams_finished: u64,
    pub connection_rejects: u64,
    pub stream_rejects: u64,
    pub path_changes: u64,
    pub metrics_snapshots: u64,
    pub shutdown_started: u64,
    pub shutdown_forced: u64,
    pub shutdown_complete: u64,
    pub forced_shutdown_completions: u64,
    pub task_failures: u64,
    pub path_event_lag_reports: u64,
    pub unknown_events: u64,
    pub latest_metrics: Option<ProxyMetricsSnapshot>,
    connection_balance: HashMap<u64, i64>,
    stream_balance: HashMap<u64, i64>,
}

impl ProxyRoleObservation {
    fn to_json(&self) -> Value {
        json!({
            "runtime_started": self.runtime_started,
            "startup_failed": self.startup_failed,
            "runtime_failed": self.runtime_failed,
            "credential_reloads": self.credential_reloads,
            "credential_reload_failures": self.credential_reload_failures,
            "connection_failures": self.connection_failures,
            "stream_failures": self.stream_failures,
            "timeout_events": self.timeout_events,
            "upstream_error_events": self.upstream_error_events,
            "connections_started": self.connections_started,
            "connections_finished": self.connections_finished,
            "streams_started": self.streams_started,
            "streams_finished": self.streams_finished,
            "connection_rejects": self.connection_rejects,
            "stream_rejects": self.stream_rejects,
            "path_changes": self.path_changes,
            "metrics_snapshots": self.metrics_snapshots,
            "shutdown_started": self.shutdown_started,
            "shutdown_forced": self.shutdown_forced,
            "shutdown_complete": self.shutdown_complete,
            "forced_shutdown_completions": self.forced_shutdown_completions,
            "task_failures": self.task_failures,
            "path_event_lag_reports": self.path_event_lag_reports,
            "unknown_events": self.unknown_events,
            "unclosed_connection_ids": nonzero_balances(&self.connection_balance),
            "unclosed_stream_groups": nonzero_balances(&self.stream_balance),
            "latest_metrics": self.latest_metrics.map(metrics_to_json),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyObservation {
    pub lines: u64,
    pub empty_lines: u64,
    pub valid_events: u64,
    pub malformed_lines: u64,
    pub oversized_lines: u64,
    pub schema_mismatches: u64,
    pub invalid_events: u64,
    pub client: ProxyRoleObservation,
    pub server: ProxyRoleObservation,
}

impl ProxyObservation {
    pub fn ingest_line(&mut self, line: &str) {
        self.lines += 1;
        if line.len() > MAX_PROXY_EVENT_LINE_BYTES {
            self.oversized_lines += 1;
            return;
        }
        let line = line.trim();
        if line.is_empty() {
            self.empty_lines += 1;
            return;
        }

        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(_) => {
                self.malformed_lines += 1;
                return;
            }
        };
        let Some(record) = value.as_object() else {
            self.invalid_events += 1;
            return;
        };
        match record.get("schema").and_then(Value::as_str) {
            Some(PROXY_EVENT_SCHEMA) => {}
            Some(_) => {
                self.schema_mismatches += 1;
                return;
            }
            None => {
                self.invalid_events += 1;
                return;
            }
        }
        if record.get("ts_unix_ms").and_then(Value::as_u64).is_none()
            || !matches!(
                record.get("level").and_then(Value::as_str),
                Some("info" | "warn" | "error")
            )
        {
            self.invalid_events += 1;
            return;
        }
        let role = match record.get("role").and_then(Value::as_str) {
            Some("client") => &mut self.client,
            Some("server") => &mut self.server,
            _ => {
                self.invalid_events += 1;
                return;
            }
        };
        let Some(event) = record.get("event").and_then(Value::as_str) else {
            self.invalid_events += 1;
            return;
        };

        self.valid_events += 1;
        if !ingest_role_event(role, event, record) {
            self.invalid_events += 1;
        }
    }

    pub fn evaluate(&self, policy: ProxyHealthPolicy) -> ProxyHealthReport {
        let mut violations = Vec::new();
        if self.valid_events == 0 {
            violations.push("no_valid_events".to_owned());
        }
        if self.malformed_lines != 0 {
            violations.push("malformed_jsonl".to_owned());
        }
        if self.oversized_lines != 0 {
            violations.push("oversized_jsonl_line".to_owned());
        }
        if self.schema_mismatches != 0 {
            violations.push("schema_mismatch".to_owned());
        }
        if self.invalid_events != 0 {
            violations.push("invalid_event".to_owned());
        }

        evaluate_role(
            "client",
            &self.client,
            policy.require_client,
            policy,
            &mut violations,
        );
        evaluate_role(
            "server",
            &self.server,
            policy.require_server,
            policy,
            &mut violations,
        );

        ProxyHealthReport {
            healthy: violations.is_empty(),
            violations,
            observation: self.clone(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": PROXY_OBSERVATION_SCHEMA,
            "lines": self.lines,
            "empty_lines": self.empty_lines,
            "valid_events": self.valid_events,
            "malformed_lines": self.malformed_lines,
            "oversized_lines": self.oversized_lines,
            "schema_mismatches": self.schema_mismatches,
            "invalid_events": self.invalid_events,
            "client": self.client.to_json(),
            "server": self.server.to_json(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHealthPolicy {
    pub require_client: bool,
    pub require_server: bool,
    pub require_clean_shutdown: bool,
    pub require_final_inactive: bool,
    pub require_closed_lifecycles: bool,
    pub max_rejections: u64,
    pub max_timeouts: u64,
    pub max_upstream_errors: u64,
    pub max_forced_shutdowns: u64,
    pub max_runtime_failures: u64,
}

impl ProxyHealthPolicy {
    pub const fn strict_both() -> Self {
        Self {
            require_client: true,
            require_server: true,
            require_clean_shutdown: true,
            require_final_inactive: true,
            require_closed_lifecycles: true,
            max_rejections: 0,
            max_timeouts: 0,
            max_upstream_errors: 0,
            max_forced_shutdowns: 0,
            max_runtime_failures: 0,
        }
    }

    pub const fn client_only() -> Self {
        Self {
            require_server: false,
            ..Self::strict_both()
        }
    }

    pub const fn server_only() -> Self {
        Self {
            require_client: false,
            ..Self::strict_both()
        }
    }
}

impl Default for ProxyHealthPolicy {
    fn default() -> Self {
        Self::strict_both()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHealthReport {
    pub healthy: bool,
    pub violations: Vec<String>,
    pub observation: ProxyObservation,
}

impl ProxyHealthReport {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": PROXY_OBSERVATION_SCHEMA,
            "healthy": self.healthy,
            "violations": self.violations,
            "summary": self.observation.to_json(),
        })
    }
}

pub fn analyze_proxy_jsonl(mut reader: impl BufRead) -> LabResult<ProxyObservation> {
    let mut observation = ProxyObservation::default();
    let mut line = Vec::with_capacity(4096);
    let mut oversized = false;
    loop {
        let (consumed, line_finished, input_finished) = {
            let available = reader
                .fill_buf()
                .map_err(|error| other_error(format!("无法读取代理 JSONL：{error}")))?;
            if available.is_empty() {
                (0, false, true)
            } else {
                let newline = available.iter().position(|byte| *byte == b'\n');
                let content_length = newline.unwrap_or(available.len());
                if !oversized {
                    if line.len().saturating_add(content_length) > MAX_PROXY_EVENT_LINE_BYTES {
                        oversized = true;
                        line.clear();
                    } else {
                        line.extend_from_slice(&available[..content_length]);
                    }
                }
                (
                    content_length + usize::from(newline.is_some()),
                    newline.is_some(),
                    false,
                )
            }
        };
        reader.consume(consumed);

        if line_finished {
            ingest_buffered_line(&mut observation, &line, oversized);
            line.clear();
            oversized = false;
        }
        if input_finished {
            if oversized || !line.is_empty() {
                ingest_buffered_line(&mut observation, &line, oversized);
            }
            break;
        }
    }
    Ok(observation)
}

fn ingest_buffered_line(observation: &mut ProxyObservation, line: &[u8], oversized: bool) {
    if oversized {
        observation.lines += 1;
        observation.oversized_lines += 1;
        return;
    }
    match std::str::from_utf8(line) {
        Ok(line) => observation.ingest_line(line),
        Err(_) => {
            observation.lines += 1;
            observation.malformed_lines += 1;
        }
    }
}

fn ingest_role_event(
    role: &mut ProxyRoleObservation,
    event: &str,
    record: &Map<String, Value>,
) -> bool {
    match event {
        "runtime_started" => {
            if !has_string(record, "listen") || !has_string(record, "transport") {
                return false;
            }
            role.runtime_started += 1;
        }
        "startup_failed" => {
            let Some(reason) = record.get("reason").and_then(Value::as_str) else {
                return false;
            };
            role.startup_failed += 1;
            role.timeout_events += u64::from(is_timeout_reason(reason));
        }
        "runtime_failed" => {
            if !has_string(record, "reason") {
                return false;
            }
            role.runtime_failed += 1;
        }
        "credentials_reloaded" => {
            if record.get("kind").and_then(Value::as_str) != Some("token")
                || !matches!(
                    record.get("accepted_token_count").and_then(Value::as_u64),
                    Some(1 | 2)
                )
            {
                return false;
            }
            role.credential_reloads += 1;
        }
        "credentials_reload_failed" => {
            if record.get("kind").and_then(Value::as_str) != Some("token")
                || record.get("reason").and_then(Value::as_str) != Some("token_reload_failed")
            {
                return false;
            }
            role.credential_reload_failures += 1;
        }
        "connection_started" => {
            let Some(connection_id) = record.get("connection_id").and_then(Value::as_u64) else {
                return false;
            };
            role.connections_started += 1;
            adjust_balance(&mut role.connection_balance, connection_id, 1);
        }
        "connection_finished" => {
            let Some(reason) = record.get("reason").and_then(Value::as_str) else {
                return false;
            };
            let Some(connection_id) = record.get("connection_id").and_then(Value::as_u64) else {
                return false;
            };
            role.connections_finished += 1;
            adjust_balance(&mut role.connection_balance, connection_id, -1);
            role.connection_failures += u64::from(!matches!(
                reason,
                "shutdown" | "shutdown_forced" | "peer_closed"
            ));
        }
        "stream_started" => {
            let Some(connection_id) = record.get("connection_id").and_then(Value::as_u64) else {
                return false;
            };
            role.streams_started += 1;
            adjust_balance(&mut role.stream_balance, connection_id, 1);
        }
        "stream_finished" => {
            let Some(reason) = record.get("reason").and_then(Value::as_str) else {
                return false;
            };
            let Some(connection_id) = record.get("connection_id").and_then(Value::as_u64) else {
                return false;
            };
            role.streams_finished += 1;
            adjust_balance(&mut role.stream_balance, connection_id, -1);
            role.stream_failures += u64::from(reason != "completed");
            role.timeout_events += u64::from(is_timeout_reason(reason));
            role.upstream_error_events += u64::from(is_upstream_error_reason(reason));
        }
        "connection_rejected" => {
            if !has_string(record, "reason") {
                return false;
            }
            role.connection_rejects += 1;
        }
        "stream_rejected" => {
            if !has_string(record, "reason") {
                return false;
            }
            role.stream_rejects += 1;
        }
        "path_changed" => {
            if !has_u64(record, "connection_id") || !has_string(record, "change") {
                return false;
            }
            role.path_changes += 1;
        }
        "metrics_snapshot" => {
            let Some(metrics) = parse_metrics(record) else {
                return false;
            };
            role.metrics_snapshots += 1;
            role.latest_metrics = Some(metrics);
        }
        "shutdown_started" => {
            if !has_u64(record, "drain_timeout_ms") {
                return false;
            }
            role.shutdown_started += 1;
        }
        "shutdown_forced" => {
            if !has_string(record, "reason") {
                return false;
            }
            role.shutdown_forced += 1;
        }
        "shutdown_complete" => {
            let Some(forced) = record.get("forced").and_then(Value::as_bool) else {
                return false;
            };
            if !has_u64(record, "drain_ms") {
                return false;
            }
            role.shutdown_complete += 1;
            role.forced_shutdown_completions += u64::from(forced);
        }
        "connection_task_failed" | "stream_task_failed" => {
            if !has_string(record, "reason") {
                return false;
            }
            role.task_failures += 1;
        }
        "path_events_lagged" => {
            if !has_u64(record, "connection_id") || !has_u64(record, "lost_events") {
                return false;
            }
            role.path_event_lag_reports += 1;
        }
        "connection_failed" => {
            let Some(reason) = record.get("reason").and_then(Value::as_str) else {
                return false;
            };
            role.connection_failures += u64::from(reason != "shutdown");
            role.timeout_events += u64::from(is_timeout_reason(reason));
        }
        _ => role.unknown_events += 1,
    }
    true
}

fn evaluate_role(
    name: &str,
    role: &ProxyRoleObservation,
    required: bool,
    policy: ProxyHealthPolicy,
    violations: &mut Vec<String>,
) {
    let observed = role != &ProxyRoleObservation::default();
    if (required || observed) && role.runtime_started == 0 {
        violations.push(format!("{name}.missing_runtime"));
    }
    if !observed {
        return;
    }

    let runtime_failures = saturating_sum([
        role.startup_failed,
        role.runtime_failed,
        role.credential_reload_failures,
        role.task_failures,
        role.path_event_lag_reports,
        role.connection_failures,
        role.stream_failures,
    ]);
    if runtime_failures > policy.max_runtime_failures {
        violations.push(format!("{name}.runtime_failures_exceeded"));
    }
    if policy.require_closed_lifecycles {
        if role.connections_started != role.connections_finished
            || has_nonzero_balance(&role.connection_balance)
        {
            violations.push(format!("{name}.connection_lifecycle_open"));
        }
        if role.streams_started != role.streams_finished
            || has_nonzero_balance(&role.stream_balance)
        {
            violations.push(format!("{name}.stream_lifecycle_open"));
        }
    }

    if policy.require_clean_shutdown {
        if role.shutdown_complete != role.runtime_started {
            violations.push(format!("{name}.shutdown_lifecycle_open"));
        }
        if role.shutdown_started != role.shutdown_complete {
            violations.push(format!("{name}.shutdown_sequence_invalid"));
        }
    }

    let event_forced = role.shutdown_forced.max(role.forced_shutdown_completions);
    let Some(metrics) = role.latest_metrics else {
        if role.connection_rejects.saturating_add(role.stream_rejects) > policy.max_rejections {
            violations.push(format!("{name}.rejections_exceeded"));
        }
        violations.push(format!("{name}.missing_metrics"));
        return;
    };
    let rejections = role
        .connection_rejects
        .saturating_add(role.stream_rejects)
        .max(
            metrics
                .connection_rejects
                .saturating_add(metrics.stream_rejects),
        );
    if rejections > policy.max_rejections {
        violations.push(format!("{name}.rejections_exceeded"));
    }
    if policy.require_final_inactive {
        if metrics.active_connections != 0 {
            violations.push(format!("{name}.active_connections_nonzero"));
        }
        if metrics.active_streams != 0 {
            violations.push(format!("{name}.active_streams_nonzero"));
        }
    }
    if policy.require_clean_shutdown
        && metrics
            .graceful_shutdowns
            .saturating_add(metrics.forced_shutdowns)
            != 1
    {
        violations.push(format!("{name}.shutdown_metrics_invalid"));
    }
    let forced_shutdowns = event_forced.max(metrics.forced_shutdowns);
    if forced_shutdowns > policy.max_forced_shutdowns {
        violations.push(format!("{name}.forced_shutdowns_exceeded"));
    }
    let timeouts = role.timeout_events.max(saturating_sum([
        metrics.dns_timeouts,
        metrics.handshake_timeouts,
        metrics.request_timeouts,
        metrics.stream_open_timeouts,
        metrics.upstream_connect_timeouts,
    ]));
    if timeouts > policy.max_timeouts {
        violations.push(format!("{name}.timeouts_exceeded"));
    }
    let upstream_errors = role.upstream_error_events.max(metrics.upstream_errors);
    if upstream_errors > policy.max_upstream_errors {
        violations.push(format!("{name}.upstream_errors_exceeded"));
    }
}

fn is_timeout_reason(reason: &str) -> bool {
    matches!(
        reason,
        "dns_timeout"
            | "handshake_timeout"
            | "handshake_confirmation_timeout"
            | "request_timeout"
            | "request_negotiation_timeout"
            | "stream_open_timeout"
            | "upstream_connect_timeout"
    )
}

fn is_upstream_error_reason(reason: &str) -> bool {
    matches!(
        reason,
        "upstream_connect_failed" | "upstream_connect_timeout" | "server_rejected_upstream"
    )
}

fn has_u64(record: &Map<String, Value>, key: &str) -> bool {
    record.get(key).and_then(Value::as_u64).is_some()
}

fn has_nonzero_balance(balances: &HashMap<u64, i64>) -> bool {
    balances.values().any(|balance| *balance != 0)
}

fn adjust_balance(balances: &mut HashMap<u64, i64>, key: u64, delta: i64) {
    let remove = {
        let balance = balances.entry(key).or_default();
        *balance += delta;
        *balance == 0
    };
    if remove {
        balances.remove(&key);
    }
}

fn saturating_sum<const N: usize>(values: [u64; N]) -> u64 {
    values
        .into_iter()
        .fold(0_u64, |sum, value| sum.saturating_add(value))
}

fn nonzero_balances(balances: &HashMap<u64, i64>) -> usize {
    balances.values().filter(|balance| **balance != 0).count()
}

fn has_string(record: &Map<String, Value>, key: &str) -> bool {
    record.get(key).and_then(Value::as_str).is_some()
}

fn parse_metrics(record: &Map<String, Value>) -> Option<ProxyMetricsSnapshot> {
    let metric = |name| record.get(name).and_then(Value::as_u64);
    Some(ProxyMetricsSnapshot {
        active_connections: metric("active_connections")?,
        total_connections: metric("total_connections")?,
        connection_rejects: metric("connection_rejects")?,
        active_streams: metric("active_streams")?,
        total_streams: metric("total_streams")?,
        stream_rejects: metric("stream_rejects")?,
        dns_timeouts: metric("dns_timeouts")?,
        handshake_timeouts: metric("handshake_timeouts")?,
        request_timeouts: metric("request_timeouts")?,
        stream_open_timeouts: metric("stream_open_timeouts")?,
        upstream_connect_timeouts: metric("upstream_connect_timeouts")?,
        upstream_errors: metric("upstream_errors")?,
        upload_bytes: metric("upload_bytes")?,
        download_bytes: metric("download_bytes")?,
        graceful_shutdowns: metric("graceful_shutdowns")?,
        forced_shutdowns: metric("forced_shutdowns")?,
    })
}

fn metrics_to_json(metrics: ProxyMetricsSnapshot) -> Value {
    json!({
        "active_connections": metrics.active_connections,
        "total_connections": metrics.total_connections,
        "connection_rejects": metrics.connection_rejects,
        "active_streams": metrics.active_streams,
        "total_streams": metrics.total_streams,
        "stream_rejects": metrics.stream_rejects,
        "dns_timeouts": metrics.dns_timeouts,
        "handshake_timeouts": metrics.handshake_timeouts,
        "request_timeouts": metrics.request_timeouts,
        "stream_open_timeouts": metrics.stream_open_timeouts,
        "upstream_connect_timeouts": metrics.upstream_connect_timeouts,
        "upstream_errors": metrics.upstream_errors,
        "upload_bytes": metrics.upload_bytes,
        "download_bytes": metrics.download_bytes,
        "graceful_shutdowns": metrics.graceful_shutdowns,
        "forced_shutdowns": metrics.forced_shutdowns,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn base(role: &str, event: &str) -> Map<String, Value> {
        json!({
            "schema": PROXY_EVENT_SCHEMA,
            "ts_unix_ms": 1,
            "level": "info",
            "role": role,
            "event": event,
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn push(lines: &mut Vec<String>, role: &str, event: &str, fields: Value) {
        let mut record = base(role, event);
        record.extend(fields.as_object().unwrap().clone());
        lines.push(serde_json::to_string(&record).unwrap());
    }

    fn metrics() -> Value {
        json!({
            "active_connections": 0,
            "total_connections": 1,
            "connection_rejects": 0,
            "active_streams": 0,
            "total_streams": 1,
            "stream_rejects": 0,
            "dns_timeouts": 0,
            "handshake_timeouts": 0,
            "request_timeouts": 0,
            "stream_open_timeouts": 0,
            "upstream_connect_timeouts": 0,
            "upstream_errors": 0,
            "upload_bytes": 4,
            "download_bytes": 4,
            "graceful_shutdowns": 1,
            "forced_shutdowns": 0,
        })
    }

    fn healthy_fixture() -> String {
        let mut lines = Vec::new();
        for role in ["client", "server"] {
            push(
                &mut lines,
                role,
                "runtime_started",
                json!({"listen": "127.0.0.1:1", "transport": "tcp"}),
            );
            push(
                &mut lines,
                role,
                "connection_started",
                json!({"connection_id": 7}),
            );
            push(
                &mut lines,
                role,
                "stream_started",
                json!({"connection_id": 7}),
            );
            push(
                &mut lines,
                role,
                "stream_finished",
                json!({"connection_id": 7, "reason": "completed"}),
            );
            push(
                &mut lines,
                role,
                "connection_finished",
                json!({"connection_id": 7, "reason": "shutdown"}),
            );
            push(
                &mut lines,
                role,
                "credentials_reloaded",
                json!({"kind": "token", "accepted_token_count": 1}),
            );
            push(
                &mut lines,
                role,
                "shutdown_started",
                json!({"drain_timeout_ms": 10000}),
            );
            push(&mut lines, role, "metrics_snapshot", metrics());
            push(
                &mut lines,
                role,
                "shutdown_complete",
                json!({"forced": false, "drain_ms": 2}),
            );
        }
        lines.join("\n")
    }

    #[test]
    fn strict_health_accepts_closed_client_and_server_lifecycles() {
        let observation = analyze_proxy_jsonl(Cursor::new(healthy_fixture())).unwrap();
        let report = observation.evaluate(ProxyHealthPolicy::strict_both());
        assert!(report.healthy, "{:?}", report.violations);
        assert_eq!(observation.client.streams_started, 1);
        assert_eq!(observation.server.streams_finished, 1);
        assert_eq!(observation.client.credential_reloads, 1);
        assert_eq!(observation.server.credential_reload_failures, 0);
        assert_eq!(report.to_json()["schema"], PROXY_OBSERVATION_SCHEMA);
    }

    #[test]
    fn failed_credential_reload_uses_existing_runtime_failure_threshold() {
        let mut fixture = healthy_fixture();
        let mut lines = Vec::new();
        push(
            &mut lines,
            "server",
            "credentials_reload_failed",
            json!({"kind": "token", "reason": "token_reload_failed"}),
        );
        fixture.push('\n');
        fixture.push_str(&lines[0]);

        let observation = analyze_proxy_jsonl(Cursor::new(fixture)).unwrap();
        assert_eq!(observation.server.credential_reload_failures, 1);
        let strict = observation.evaluate(ProxyHealthPolicy::strict_both());
        assert!(!strict.healthy);
        assert!(
            strict
                .violations
                .contains(&"server.runtime_failures_exceeded".to_owned())
        );

        let policy = ProxyHealthPolicy {
            max_runtime_failures: 1,
            ..ProxyHealthPolicy::strict_both()
        };
        assert!(observation.evaluate(policy).healthy);
    }

    #[test]
    fn malformed_schema_and_open_lifecycle_are_stable_violations() {
        let mut fixture = healthy_fixture();
        fixture.push_str("\nnot-json\n");
        fixture.push_str(
            &json!({
                "schema": "foreign.v1",
                "ts_unix_ms": 1,
                "level": "info",
                "role": "client",
                "event": "stream_started",
                "connection_id": 7,
            })
            .to_string(),
        );
        fixture.push('\n');
        fixture.push_str(&"x".repeat(MAX_PROXY_EVENT_LINE_BYTES + 1));
        let mut observation = analyze_proxy_jsonl(Cursor::new(fixture)).unwrap();
        observation.client.streams_started += 1;
        observation.client.connection_balance.insert(7, 1);
        observation.client.connection_balance.insert(8, -1);
        let report = observation.evaluate(ProxyHealthPolicy::strict_both());
        assert!(!report.healthy);
        assert!(report.violations.contains(&"malformed_jsonl".to_owned()));
        assert!(report.violations.contains(&"schema_mismatch".to_owned()));
        assert!(
            report
                .violations
                .contains(&"oversized_jsonl_line".to_owned())
        );
        assert!(
            report
                .violations
                .contains(&"client.stream_lifecycle_open".to_owned())
        );
        assert!(
            report
                .violations
                .contains(&"client.connection_lifecycle_open".to_owned())
        );
    }

    #[test]
    fn explicit_threshold_can_allow_a_known_rejection() {
        let mut observation = analyze_proxy_jsonl(Cursor::new(healthy_fixture())).unwrap();
        observation.client.connection_rejects = 1;
        assert!(
            !observation
                .evaluate(ProxyHealthPolicy::strict_both())
                .healthy
        );
        let policy = ProxyHealthPolicy {
            max_rejections: 1,
            ..ProxyHealthPolicy::strict_both()
        };
        assert!(observation.evaluate(policy).healthy);
    }

    #[test]
    fn failed_stream_reason_cannot_hide_behind_closed_gauges() {
        let mut observation = analyze_proxy_jsonl(Cursor::new(healthy_fixture())).unwrap();
        observation.client.stream_failures = 1;
        observation.client.timeout_events = 1;
        let report = observation.evaluate(ProxyHealthPolicy::strict_both());
        assert!(!report.healthy);
        assert!(
            report
                .violations
                .contains(&"client.runtime_failures_exceeded".to_owned())
        );
        assert!(
            report
                .violations
                .contains(&"client.timeouts_exceeded".to_owned())
        );
    }

    #[test]
    fn live_summary_policy_can_keep_expected_lifecycles_open() {
        let observation = ProxyObservation {
            valid_events: 1,
            client: ProxyRoleObservation {
                runtime_started: 1,
                connections_started: 1,
                streams_started: 1,
                metrics_snapshots: 1,
                latest_metrics: Some(ProxyMetricsSnapshot {
                    active_connections: 1,
                    active_streams: 1,
                    total_connections: 1,
                    total_streams: 1,
                    ..ProxyMetricsSnapshot::default()
                }),
                ..ProxyRoleObservation::default()
            },
            ..ProxyObservation::default()
        };
        let policy = ProxyHealthPolicy {
            require_clean_shutdown: false,
            require_final_inactive: false,
            require_closed_lifecycles: false,
            ..ProxyHealthPolicy::client_only()
        };
        assert!(observation.evaluate(policy).healthy);
    }
}
