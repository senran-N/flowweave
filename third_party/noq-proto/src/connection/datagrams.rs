use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    FrameStats, TransportError,
    connection::{PacketBuilder, PathId},
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        self.send_inner(data, None, false, drop)
    }

    /// Queue an unreliable, unordered datagram for transmission on one exact local path.
    ///
    /// The target must already be validated and open. A targeted datagram may use a Backup path,
    /// but remains subject to that path's congestion window, pacing and MTU. It is never silently
    /// moved to another path if the target later closes.
    pub fn send_on_path(
        &mut self,
        path_id: PathId,
        data: Bytes,
        drop: bool,
    ) -> Result<(), SendDatagramOnPathError> {
        let path_is_usable = self
            .conn
            .paths
            .get(&path_id)
            .is_some_and(|path| path.data.validated)
            && !self.conn.abandoned_paths.contains(&path_id)
            && self.conn.remote_cids.contains_key(&path_id);
        if !path_is_usable {
            return Err(SendDatagramOnPathError::PathUnavailable(path_id));
        }
        self.send_inner(data, Some(path_id), false, drop)?;
        Ok(())
    }

    /// Queue a targeted datagram which must not share a QUIC packet with another application
    /// DATAGRAM frame.
    ///
    /// ACK and control frames may still share the packet. The boundary changes neither path
    /// selection nor congestion, pacing, MTU, anti-amplification, and buffering constraints.
    pub fn send_on_path_separate(
        &mut self,
        path_id: PathId,
        data: Bytes,
        drop: bool,
    ) -> Result<(), SendDatagramOnPathError> {
        let path_is_usable = self
            .conn
            .paths
            .get(&path_id)
            .is_some_and(|path| path.data.validated)
            && !self.conn.abandoned_paths.contains(&path_id)
            && self.conn.remote_cids.contains_key(&path_id);
        if !path_is_usable {
            return Err(SendDatagramOnPathError::PathUnavailable(path_id));
        }
        self.send_inner(data, Some(path_id), true, drop)?;
        Ok(())
    }

    fn send_inner(
        &mut self,
        data: Bytes,
        path_id: Option<PathId>,
        separate: bool,
        drop: bool,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            while self.conn.datagrams.outgoing_total > self.conn.config.datagram_send_buffer_size {
                let prev = self
                    .conn
                    .datagrams
                    .outgoing
                    .pop_front()
                    .expect("datagrams.outgoing_total desynchronized");
                trace!(len = prev.frame.data.len(), "dropping outgoing datagram");
                self.conn.datagrams.outgoing_total -= prev.frame.data.len();
            }
        } else if self.conn.datagrams.outgoing_total + data.len()
            > self.conn.config.datagram_send_buffer_size
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.outgoing.push_back(OutgoingDatagram {
            frame: Datagram { data },
            path_id,
            separate,
        });
        Ok(())
    }

    /// Compute the maximum size of datagrams that may be passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// When multipath is enabled, this is calculated using the smallest MTU across all
    /// available paths.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.current_mtu() as usize
            - self.conn.predict_1rtt_overhead_no_pn()
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<Datagram>,
    pub(super) outgoing: VecDeque<OutgoingDatagram>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.recv_buffered == 0;
        while datagram.data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        self.outgoing.retain(|datagram| {
            let result = datagram.frame.data.len() < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.frame.data.len(),
                    max_payload
                );
                self.outgoing_total -= datagram.frame.data.len();
                dropped_any = true;
            }
            result
        });
        dropped_any
    }

    /// Drop queued copies bound to a path which can no longer transmit them.
    pub(super) fn drop_targeted_path(&mut self, path_id: PathId) -> bool {
        let mut dropped_bytes = 0usize;
        self.outgoing.retain(|datagram| {
            let keep = datagram.path_id != Some(path_id);
            if !keep {
                dropped_bytes = dropped_bytes.saturating_add(datagram.frame.data.len());
            }
            keep
        });
        self.outgoing_total = self.outgoing_total.saturating_sub(dropped_bytes);
        dropped_bytes != 0
    }

    pub(super) fn has_untargeted(&self, max_size: usize) -> bool {
        self.outgoing
            .iter()
            .any(|datagram| datagram.path_id.is_none() && datagram.frame.size(true) <= max_size)
    }

    pub(super) fn has_targeted(&self, path_id: PathId, max_size: usize) -> bool {
        self.outgoing.iter().any(|datagram| {
            datagram.path_id == Some(path_id) && datagram.frame.size(true) <= max_size
        })
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write<'a, 'b>(
        &mut self,
        path_id: PathId,
        allow_untargeted: bool,
        application_datagrams_written: bool,
        buf: &mut PacketBuilder<'a, 'b>,
        stat: &mut FrameStats,
    ) -> DatagramWriteStatus {
        let Some(index) = self.outgoing.iter().position(|datagram| {
            datagram.path_id == Some(path_id) || (allow_untargeted && datagram.path_id.is_none())
        }) else {
            return DatagramWriteStatus::Nothing;
        };
        if application_datagrams_written && self.outgoing[index].separate {
            return DatagramWriteStatus::NeedsFreshPacket;
        }
        let datagram = self
            .outgoing
            .remove(index)
            .expect("selected outgoing datagram must still exist");

        if buf.frame_space_remaining() < datagram.frame.size(true) {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.insert(index, datagram);
            return DatagramWriteStatus::Nothing;
        }

        self.outgoing_total -= datagram.frame.data.len();
        let stop_packet = datagram.separate;
        buf.write_frame(datagram.frame, stat);
        DatagramWriteStatus::Wrote { stop_packet }
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        self.recv_buffered -= x.len();
        Some(x)
    }
}

#[derive(Debug)]
pub(super) struct OutgoingDatagram {
    frame: Datagram,
    path_id: Option<PathId>,
    separate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DatagramWriteStatus {
    Nothing,
    NeedsFreshPacket,
    Wrote { stop_packet: bool },
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}

/// Errors that can arise when binding an application datagram to one exact local path.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramOnPathError {
    /// The ordinary DATAGRAM send constraints were not satisfied.
    #[error(transparent)]
    Datagram(#[from] SendDatagramError),
    /// The requested path does not exist, is not validated, or has already been abandoned.
    #[error("datagram target path {0} is unavailable")]
    PathUnavailable(PathId),
}
