use std::{
    collections::BTreeMap,
    ops::{Bound, Range},
};

use rustc_hash::FxHashMap;
use thiserror::Error;

use super::PathId;
use crate::{Duration, Instant, StreamId, frame};

pub(crate) const COHORT_DURATION: Duration = Duration::from_millis(250);
const ACK_DRAIN: Duration = Duration::from_secs(1);
const FINAL_RETENTION: Duration = Duration::from_millis(1_500);

/// Error returned when an application cannot declare a diagnostic backlogged epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeclaredBackloggedEpochError {
    /// The transport configuration did not enable the default-off diagnostic sensor.
    #[error("the declared-backlogged epoch sensor is disabled")]
    Disabled,
    /// This connection already declared an epoch; epochs cannot be restarted or replaced.
    #[error("a declared-backlogged epoch was already started")]
    AlreadyStarted,
    /// The duration was zero, not an exact number of 250 ms cohorts, or too large.
    #[error("the declared-backlogged epoch duration is invalid")]
    InvalidDuration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) declared_cohorts: u64,
    pub(crate) settled_cohorts: u64,
    pub(crate) empty_cohorts: u64,
    pub(crate) fresh_bytes: u64,
    pub(crate) acked_bytes: u64,
    pub(crate) late_acked_bytes: u64,
    pub(crate) bytes_missing_at_drain: u64,
    pub(crate) pending_cohorts: u64,
    pub(crate) pending_origin_bytes: u64,
    pub(crate) tracked_origin_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct Origin {
    end: u64,
    path: PathId,
    cohort: usize,
}

#[derive(Debug)]
struct PathEpoch {
    fresh_bytes: Vec<u64>,
    acked_bytes: Vec<u64>,
    late_acked_bytes: u64,
    bytes_missing_at_drain: u64,
}

impl PathEpoch {
    fn new(cohorts: usize) -> Self {
        Self {
            fresh_bytes: vec![0; cohorts],
            acked_bytes: vec![0; cohorts],
            late_acked_bytes: 0,
            bytes_missing_at_drain: 0,
        }
    }
}

#[derive(Debug)]
struct Epoch {
    start: Instant,
    end: Instant,
    cohorts: usize,
    last_advanced: Instant,
    paths: FxHashMap<PathId, PathEpoch>,
    pending: BTreeMap<(StreamId, u64), Origin>,
    late: BTreeMap<(StreamId, u64), Origin>,
}

impl Epoch {
    fn cohort_end(&self, cohort: usize) -> Instant {
        self.start
            + COHORT_DURATION
                .saturating_mul(u32::try_from(cohort.saturating_add(1)).unwrap_or(u32::MAX))
    }

    fn cohort_deadline(&self, cohort: usize) -> Instant {
        self.cohort_end(cohort) + ACK_DRAIN
    }

    fn final_retention_end(&self) -> Instant {
        self.end + FINAL_RETENTION
    }

    fn path_mut(&mut self, path: PathId) -> &mut PathEpoch {
        self.paths
            .entry(path)
            .or_insert_with(|| PathEpoch::new(self.cohorts))
    }

    fn cohort_at(&self, now: Instant) -> Option<usize> {
        if now < self.start || now >= self.end {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.start).as_nanos();
        let cohort = usize::try_from(elapsed / COHORT_DURATION.as_nanos()).ok()?;
        (cohort < self.cohorts).then_some(cohort)
    }

    fn settled_cohorts(&self) -> usize {
        (0..self.cohorts)
            .take_while(|cohort| self.cohort_deadline(*cohort) <= self.last_advanced)
            .count()
    }

    fn advance(&mut self, now: Instant) {
        self.last_advanced = self.last_advanced.max(now);

        let expired = self
            .pending
            .iter()
            .filter(|(_, origin)| self.cohort_deadline(origin.cohort) <= now)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in expired {
            let Some(origin) = self.pending.remove(&key) else {
                continue;
            };
            let bytes = origin.end.saturating_sub(key.1);
            self.path_mut(origin.path).bytes_missing_at_drain = self
                .path_mut(origin.path)
                .bytes_missing_at_drain
                .saturating_add(bytes);
            self.late.insert(key, origin);
        }

        if now >= self.final_retention_end() {
            self.late.clear();
        }
    }

    fn record_fresh_frames(&mut self, now: Instant, path: PathId, frames: &[frame::StreamMeta]) {
        let Some(cohort) = self.cohort_at(now) else {
            return;
        };

        for frame in frames {
            let start = frame.offsets.start;
            let end = frame.offsets.end;
            let bytes = end.saturating_sub(start);
            if bytes == 0 {
                continue;
            }
            self.path_mut(path).fresh_bytes[cohort] =
                self.path_mut(path).fresh_bytes[cohort].saturating_add(bytes);
            let replaced = self
                .pending
                .insert((frame.id, start), Origin { end, path, cohort });
            debug_assert!(replaced.is_none(), "fresh STREAM origins must not overlap");
        }
    }

    fn record_ack(&mut self, frame: &frame::StreamMeta) {
        let timely = take_overlaps(&mut self.pending, frame.id, frame.offsets.clone());
        for (origin, bytes) in timely {
            self.path_mut(origin.path).acked_bytes[origin.cohort] =
                self.path_mut(origin.path).acked_bytes[origin.cohort].saturating_add(bytes);
        }

        let late = take_overlaps(&mut self.late, frame.id, frame.offsets.clone());
        for (origin, bytes) in late {
            self.path_mut(origin.path).late_acked_bytes = self
                .path_mut(origin.path)
                .late_acked_bytes
                .saturating_add(bytes);
        }
    }

    fn snapshot(&self, path: PathId) -> Snapshot {
        let settled = self.settled_cohorts();
        let pending_origin_bytes = origin_bytes_for_path(&self.pending, path);
        let tracked_origin_bytes =
            pending_origin_bytes.saturating_add(origin_bytes_for_path(&self.late, path));

        let Some(path_epoch) = self.paths.get(&path) else {
            return Snapshot {
                declared_cohorts: self.cohorts as u64,
                settled_cohorts: settled as u64,
                empty_cohorts: self.cohorts as u64,
                pending_cohorts: self.cohorts.saturating_sub(settled) as u64,
                pending_origin_bytes,
                tracked_origin_bytes,
                ..Snapshot::default()
            };
        };

        Snapshot {
            declared_cohorts: self.cohorts as u64,
            settled_cohorts: settled as u64,
            empty_cohorts: path_epoch
                .fresh_bytes
                .iter()
                .filter(|bytes| **bytes == 0)
                .count() as u64,
            fresh_bytes: path_epoch.fresh_bytes.iter().copied().sum(),
            acked_bytes: path_epoch.acked_bytes.iter().copied().sum(),
            late_acked_bytes: path_epoch.late_acked_bytes,
            bytes_missing_at_drain: path_epoch.bytes_missing_at_drain,
            pending_cohorts: self.cohorts.saturating_sub(settled) as u64,
            pending_origin_bytes,
            tracked_origin_bytes,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DeclaredBackloggedEpochSensor {
    enabled: bool,
    epoch: Option<Epoch>,
}

impl DeclaredBackloggedEpochSensor {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            epoch: None,
        }
    }

    pub(crate) fn start(
        &mut self,
        now: Instant,
        duration: Duration,
    ) -> Result<(), DeclaredBackloggedEpochError> {
        if !self.enabled {
            return Err(DeclaredBackloggedEpochError::Disabled);
        }
        if self.epoch.is_some() {
            return Err(DeclaredBackloggedEpochError::AlreadyStarted);
        }
        if duration.is_zero()
            || !duration
                .as_nanos()
                .is_multiple_of(COHORT_DURATION.as_nanos())
        {
            return Err(DeclaredBackloggedEpochError::InvalidDuration);
        }
        let cohorts = usize::try_from(duration.as_nanos() / COHORT_DURATION.as_nanos())
            .map_err(|_| DeclaredBackloggedEpochError::InvalidDuration)?;
        if cohorts == 0 || u32::try_from(cohorts).is_err() {
            return Err(DeclaredBackloggedEpochError::InvalidDuration);
        }

        self.epoch = Some(Epoch {
            start: now,
            end: now + duration,
            cohorts,
            last_advanced: now,
            paths: FxHashMap::default(),
            pending: BTreeMap::new(),
            late: BTreeMap::new(),
        });
        Ok(())
    }

    pub(crate) fn advance(&mut self, now: Instant) {
        if let Some(epoch) = &mut self.epoch {
            epoch.advance(now);
        }
    }

    pub(crate) fn record_fresh_frames(
        &mut self,
        now: Instant,
        path: PathId,
        frames: &[frame::StreamMeta],
    ) {
        self.advance(now);
        if let Some(epoch) = &mut self.epoch {
            epoch.record_fresh_frames(now, path, frames);
        }
    }

    pub(crate) fn record_ack(&mut self, now: Instant, frame: &frame::StreamMeta) {
        self.advance(now);
        if let Some(epoch) = &mut self.epoch {
            epoch.record_ack(frame);
        }
    }

    pub(crate) fn snapshot(&self, path: PathId) -> Snapshot {
        self.epoch
            .as_ref()
            .map_or_else(Snapshot::default, |epoch| epoch.snapshot(path))
    }
}

fn take_overlaps(
    origins: &mut BTreeMap<(StreamId, u64), Origin>,
    stream: StreamId,
    range: Range<u64>,
) -> Vec<(Origin, u64)> {
    if range.start >= range.end {
        return Vec::new();
    }

    let mut keys = Vec::new();
    if let Some((key, origin)) = origins
        .range((stream, 0)..=(stream, range.start))
        .next_back()
        && origin.end > range.start
    {
        keys.push(*key);
    }
    keys.extend(
        origins
            .range((
                Bound::Excluded((stream, range.start)),
                Bound::Excluded((stream, range.end)),
            ))
            .map(|(key, _)| *key),
    );

    let mut overlaps = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(origin) = origins.remove(&key) else {
            continue;
        };
        let overlap_start = key.1.max(range.start);
        let overlap_end = origin.end.min(range.end);
        if overlap_start >= overlap_end {
            origins.insert(key, origin);
            continue;
        }
        if key.1 < overlap_start {
            origins.insert(
                key,
                Origin {
                    end: overlap_start,
                    ..origin
                },
            );
        }
        if overlap_end < origin.end {
            origins.insert(
                (key.0, overlap_end),
                Origin {
                    end: origin.end,
                    ..origin
                },
            );
        }
        overlaps.push((origin, overlap_end - overlap_start));
    }
    overlaps
}

fn origin_bytes_for_path(origins: &BTreeMap<(StreamId, u64), Origin>, path: PathId) -> u64 {
    origins
        .iter()
        .filter(|(_, origin)| origin.path == path)
        .map(|(key, origin)| origin.end.saturating_sub(key.1))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dir, Side};

    fn stream() -> StreamId {
        StreamId::new(Side::Client, Dir::Uni, 0)
    }

    fn frame(offsets: Range<u64>) -> frame::StreamMeta {
        frame::StreamMeta {
            id: stream(),
            offsets,
            fin: false,
        }
    }

    #[test]
    fn every_declared_cohort_stays_in_the_denominator() {
        let start = Instant::now();
        let mut sensor = DeclaredBackloggedEpochSensor::new(true);
        sensor.start(start, Duration::from_secs(1)).unwrap();
        sensor.advance(start + Duration::from_millis(2_500));

        assert_eq!(
            sensor.snapshot(PathId::ZERO),
            Snapshot {
                declared_cohorts: 4,
                settled_cohorts: 4,
                empty_cohorts: 4,
                pending_cohorts: 0,
                ..Snapshot::default()
            }
        );
    }

    #[test]
    fn overlapping_and_duplicate_acks_count_each_origin_byte_once() {
        let start = Instant::now();
        let mut sensor = DeclaredBackloggedEpochSensor::new(true);
        sensor.start(start, Duration::from_secs(1)).unwrap();
        sensor.record_fresh_frames(
            start + Duration::from_millis(10),
            PathId::ZERO,
            &[frame(0..100)],
        );
        sensor.record_ack(start + Duration::from_millis(20), &frame(20..80));
        sensor.record_ack(start + Duration::from_millis(30), &frame(0..100));
        sensor.record_ack(start + Duration::from_millis(40), &frame(0..100));

        let snapshot = sensor.snapshot(PathId::ZERO);
        assert_eq!(snapshot.fresh_bytes, 100);
        assert_eq!(snapshot.acked_bytes, 100);
        assert_eq!(snapshot.pending_origin_bytes, 0);
    }

    #[test]
    fn ack_after_fixed_drain_is_late_and_tracking_is_bounded() {
        let start = Instant::now();
        let mut sensor = DeclaredBackloggedEpochSensor::new(true);
        sensor.start(start, Duration::from_secs(1)).unwrap();
        sensor.record_fresh_frames(
            start + Duration::from_millis(10),
            PathId::ZERO,
            &[frame(0..100)],
        );
        sensor.record_ack(start + Duration::from_millis(1_300), &frame(0..100));

        let late = sensor.snapshot(PathId::ZERO);
        assert_eq!(late.acked_bytes, 0);
        assert_eq!(late.late_acked_bytes, 100);
        assert_eq!(late.bytes_missing_at_drain, 100);
        assert_eq!(late.tracked_origin_bytes, 0);

        sensor.advance(start + Duration::from_millis(2_500));
        assert_eq!(sensor.snapshot(PathId::ZERO).tracked_origin_bytes, 0);
    }

    #[test]
    fn epoch_boundaries_and_default_off_are_strict() {
        let start = Instant::now();
        let mut disabled = DeclaredBackloggedEpochSensor::new(false);
        assert_eq!(
            disabled.start(start, Duration::from_secs(1)),
            Err(DeclaredBackloggedEpochError::Disabled)
        );

        let mut sensor = DeclaredBackloggedEpochSensor::new(true);
        assert_eq!(
            sensor.start(start, Duration::from_millis(300)),
            Err(DeclaredBackloggedEpochError::InvalidDuration)
        );
        sensor.start(start, Duration::from_secs(1)).unwrap();
        sensor.record_fresh_frames(
            start - Duration::from_millis(1),
            PathId::ZERO,
            &[frame(0..10)],
        );
        sensor.record_fresh_frames(
            start + Duration::from_secs(1),
            PathId::ZERO,
            &[frame(10..20)],
        );
        assert_eq!(sensor.snapshot(PathId::ZERO).fresh_bytes, 0);
        assert_eq!(
            sensor.start(start, Duration::from_secs(1)),
            Err(DeclaredBackloggedEpochError::AlreadyStarted)
        );
    }
}
