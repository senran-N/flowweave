use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

pub const VPN_IP_DATAGRAM_MAGIC: &[u8; 4] = b"FWI1";
pub const VPN_IP_DATAGRAM_HEADER_LEN: usize = 12;
pub const VPN_MAX_IP_PACKET_LEN: usize = u16::MAX as usize;
pub const VPN_MAX_IP_DATAGRAM_LEN: usize = VPN_IP_DATAGRAM_HEADER_LEN + VPN_MAX_IP_PACKET_LEN;
pub const VPN_MAX_FRAGMENTS_PER_PACKET: usize = 64;
pub const VPN_MIN_QUIC_DATAGRAM_LEN: usize =
    VPN_IP_DATAGRAM_HEADER_LEN + VPN_MAX_IP_PACKET_LEN.div_ceil(VPN_MAX_FRAGMENTS_PER_PACKET);
pub const VPN_DEFAULT_MAX_INFLIGHT_PACKETS: usize = 1024;
pub const VPN_DEFAULT_MAX_REASSEMBLY_BYTES: usize = 8 * 1024 * 1024;
pub const VPN_DEFAULT_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnPacketError {
    PacketEmpty,
    PacketTooLarge,
    DatagramCapacityTooSmall,
    TooManyFragments,
    InvalidMagic,
    FragmentEmpty,
    FragmentBounds,
    FragmentTotalChanged,
    FragmentOverlap,
    FragmentLimitExceeded,
    InvalidReassemblyLimits,
    InvalidIpVersion,
    InvalidIpv4Header,
    InvalidIpv4Length,
    InvalidIpv6Length,
    Ipv6JumbogramUnsupported,
}

impl fmt::Display for VpnPacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PacketEmpty => "vpn_packet_empty",
            Self::PacketTooLarge => "vpn_packet_too_large",
            Self::DatagramCapacityTooSmall => "vpn_datagram_capacity_too_small",
            Self::TooManyFragments => "vpn_too_many_fragments",
            Self::InvalidMagic => "vpn_invalid_magic",
            Self::FragmentEmpty => "vpn_fragment_empty",
            Self::FragmentBounds => "vpn_fragment_bounds",
            Self::FragmentTotalChanged => "vpn_fragment_total_changed",
            Self::FragmentOverlap => "vpn_fragment_overlap",
            Self::FragmentLimitExceeded => "vpn_fragment_limit_exceeded",
            Self::InvalidReassemblyLimits => "vpn_invalid_reassembly_limits",
            Self::InvalidIpVersion => "vpn_invalid_ip_version",
            Self::InvalidIpv4Header => "vpn_invalid_ipv4_header",
            Self::InvalidIpv4Length => "vpn_invalid_ipv4_length",
            Self::InvalidIpv6Length => "vpn_invalid_ipv6_length",
            Self::Ipv6JumbogramUnsupported => "vpn_ipv6_jumbogram_unsupported",
        })
    }
}

impl Error for VpnPacketError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnIpPacketMeta {
    pub source: IpAddr,
    pub destination: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnFragment<'a> {
    pub packet_id: u32,
    pub total_len: usize,
    pub offset: usize,
    pub payload: &'a [u8],
}

pub fn inspect_vpn_ip_packet(packet: &[u8]) -> Result<VpnIpPacketMeta, VpnPacketError> {
    if packet.is_empty() {
        return Err(VpnPacketError::PacketEmpty);
    }
    if packet.len() > VPN_MAX_IP_PACKET_LEN {
        return Err(VpnPacketError::PacketTooLarge);
    }

    match packet[0] >> 4 {
        4 => inspect_ipv4_packet(packet),
        6 => inspect_ipv6_packet(packet),
        _ => Err(VpnPacketError::InvalidIpVersion),
    }
}

fn inspect_ipv4_packet(packet: &[u8]) -> Result<VpnIpPacketMeta, VpnPacketError> {
    if packet.len() < 20 {
        return Err(VpnPacketError::InvalidIpv4Header);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(VpnPacketError::InvalidIpv4Header);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || total_len < header_len {
        return Err(VpnPacketError::InvalidIpv4Length);
    }

    Ok(VpnIpPacketMeta {
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
    })
}

fn inspect_ipv6_packet(packet: &[u8]) -> Result<VpnIpPacketMeta, VpnPacketError> {
    if packet.len() < 40 {
        return Err(VpnPacketError::InvalidIpv6Length);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len == 0 && packet.len() > 40 {
        return Err(VpnPacketError::Ipv6JumbogramUnsupported);
    }
    if payload_len + 40 != packet.len() {
        return Err(VpnPacketError::InvalidIpv6Length);
    }

    let mut source = [0_u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0_u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    Ok(VpnIpPacketMeta {
        source: IpAddr::V6(Ipv6Addr::from(source)),
        destination: IpAddr::V6(Ipv6Addr::from(destination)),
    })
}

pub fn encode_vpn_ip_fragments(
    packet_id: u32,
    packet: &[u8],
    max_datagram_len: usize,
) -> Result<Vec<Vec<u8>>, VpnPacketError> {
    inspect_vpn_ip_packet(packet)?;
    if max_datagram_len < VPN_MIN_QUIC_DATAGRAM_LEN {
        return Err(VpnPacketError::DatagramCapacityTooSmall);
    }
    let payload_capacity = max_datagram_len - VPN_IP_DATAGRAM_HEADER_LEN;
    let fragment_count = packet.len().div_ceil(payload_capacity);
    if fragment_count > VPN_MAX_FRAGMENTS_PER_PACKET {
        return Err(VpnPacketError::TooManyFragments);
    }

    let total_len = u16::try_from(packet.len()).map_err(|_| VpnPacketError::PacketTooLarge)?;
    let mut fragments = Vec::with_capacity(fragment_count);
    for (index, payload) in packet.chunks(payload_capacity).enumerate() {
        let offset = index
            .checked_mul(payload_capacity)
            .and_then(|offset| u16::try_from(offset).ok())
            .ok_or(VpnPacketError::FragmentBounds)?;
        let mut datagram = Vec::with_capacity(VPN_IP_DATAGRAM_HEADER_LEN + payload.len());
        datagram.extend_from_slice(VPN_IP_DATAGRAM_MAGIC);
        datagram.extend_from_slice(&packet_id.to_be_bytes());
        datagram.extend_from_slice(&total_len.to_be_bytes());
        datagram.extend_from_slice(&offset.to_be_bytes());
        datagram.extend_from_slice(payload);
        fragments.push(datagram);
    }
    Ok(fragments)
}

pub fn decode_vpn_ip_fragment(datagram: &[u8]) -> Result<VpnFragment<'_>, VpnPacketError> {
    if datagram.len() <= VPN_IP_DATAGRAM_HEADER_LEN {
        return Err(VpnPacketError::FragmentEmpty);
    }
    if &datagram[..4] != VPN_IP_DATAGRAM_MAGIC {
        return Err(VpnPacketError::InvalidMagic);
    }
    let packet_id = u32::from_be_bytes(datagram[4..8].try_into().expect("fixed header length"));
    let total_len = usize::from(u16::from_be_bytes(
        datagram[8..10].try_into().expect("fixed header length"),
    ));
    let offset = usize::from(u16::from_be_bytes(
        datagram[10..12].try_into().expect("fixed header length"),
    ));
    let payload = &datagram[VPN_IP_DATAGRAM_HEADER_LEN..];
    if total_len == 0 || offset >= total_len || payload.len() > total_len.saturating_sub(offset) {
        return Err(VpnPacketError::FragmentBounds);
    }
    Ok(VpnFragment {
        packet_id,
        total_len,
        offset,
        payload,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VpnReassemblyLimits {
    pub max_inflight_packets: usize,
    pub max_buffered_bytes: usize,
    pub fragment_timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnReassemblyStats {
    pub fragments_received: u64,
    pub fragments_rejected: u64,
    pub duplicate_fragments: u64,
    pub packets_completed: u64,
    pub completed_bytes: u64,
    pub packets_expired: u64,
    pub packets_evicted: u64,
}

impl Default for VpnReassemblyLimits {
    fn default() -> Self {
        Self {
            max_inflight_packets: VPN_DEFAULT_MAX_INFLIGHT_PACKETS,
            max_buffered_bytes: VPN_DEFAULT_MAX_REASSEMBLY_BYTES,
            fragment_timeout: VPN_DEFAULT_FRAGMENT_TIMEOUT,
        }
    }
}

#[derive(Debug)]
struct PartialPacket {
    total_len: usize,
    fragments: BTreeMap<usize, Vec<u8>>,
    received_bytes: usize,
    updated_at: Instant,
}

impl PartialPacket {
    fn new(total_len: usize, now: Instant) -> Self {
        Self {
            total_len,
            fragments: BTreeMap::new(),
            received_bytes: 0,
            updated_at: now,
        }
    }
}

#[derive(Debug)]
pub struct VpnReassembler {
    limits: VpnReassemblyLimits,
    packets: HashMap<u32, PartialPacket>,
    buffered_bytes: usize,
    stats: VpnReassemblyStats,
}

impl VpnReassembler {
    pub fn new(limits: VpnReassemblyLimits) -> Result<Self, VpnPacketError> {
        if limits.max_inflight_packets == 0
            || limits.max_buffered_bytes < VPN_MAX_IP_PACKET_LEN
            || limits.fragment_timeout.is_zero()
        {
            return Err(VpnPacketError::InvalidReassemblyLimits);
        }
        Ok(Self {
            limits,
            packets: HashMap::new(),
            buffered_bytes: 0,
            stats: VpnReassemblyStats::default(),
        })
    }

    pub fn inflight_packets(&self) -> usize {
        self.packets.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn stats(&self) -> VpnReassemblyStats {
        self.stats
    }

    pub(crate) fn contains_packet(&self, packet_id: u32) -> bool {
        self.packets.contains_key(&packet_id)
    }

    pub(crate) fn additional_buffered_bytes(
        &self,
        fragment: VpnFragment<'_>,
    ) -> Result<usize, VpnPacketError> {
        let Some(partial) = self.packets.get(&fragment.packet_id) else {
            return Ok(fragment.payload.len());
        };
        if partial.total_len != fragment.total_len {
            return Err(VpnPacketError::FragmentTotalChanged);
        }

        let fragment_end = fragment
            .offset
            .checked_add(fragment.payload.len())
            .ok_or(VpnPacketError::FragmentBounds)?;
        for (&existing_offset, existing_payload) in &partial.fragments {
            let existing_end = existing_offset + existing_payload.len();
            if existing_offset == fragment.offset && existing_payload.as_slice() == fragment.payload
            {
                return Ok(0);
            }
            if fragment.offset < existing_end && existing_offset < fragment_end {
                return Err(VpnPacketError::FragmentOverlap);
            }
        }
        if partial.fragments.len() >= VPN_MAX_FRAGMENTS_PER_PACKET {
            return Err(VpnPacketError::FragmentLimitExceeded);
        }
        Ok(fragment.payload.len())
    }

    pub(crate) fn fragment_will_complete(&self, fragment: VpnFragment<'_>) -> bool {
        let received_bytes = self
            .packets
            .get(&fragment.packet_id)
            .map_or(0, |partial| partial.received_bytes);
        received_bytes
            .checked_add(fragment.payload.len())
            .is_some_and(|received| received == fragment.total_len)
    }

    pub(crate) fn oldest_packet_updated_at(
        &self,
        excluded_packet_id: Option<u32>,
    ) -> Option<(u32, Instant)> {
        self.packets
            .iter()
            .filter(|(packet_id, _)| Some(**packet_id) != excluded_packet_id)
            .min_by_key(|(_, partial)| partial.updated_at)
            .map(|(&packet_id, partial)| (packet_id, partial.updated_at))
    }

    pub(crate) fn evict_packet(&mut self, packet_id: u32) -> bool {
        if !self.packets.contains_key(&packet_id) {
            return false;
        }
        self.remove_packet(packet_id);
        self.stats.packets_evicted = self.stats.packets_evicted.saturating_add(1);
        true
    }

    pub(crate) fn clear(&mut self) {
        self.packets.clear();
        self.buffered_bytes = 0;
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let expired = self
            .packets
            .iter()
            .filter_map(|(&packet_id, partial)| {
                (now.saturating_duration_since(partial.updated_at) >= self.limits.fragment_timeout)
                    .then_some(packet_id)
            })
            .collect::<Vec<_>>();
        let count = expired.len();
        for packet_id in expired {
            self.remove_packet(packet_id);
        }
        self.stats.packets_expired = self
            .stats
            .packets_expired
            .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        count
    }

    pub fn ingest(
        &mut self,
        now: Instant,
        datagram: &[u8],
    ) -> Result<Option<Vec<u8>>, VpnPacketError> {
        self.stats.fragments_received = self.stats.fragments_received.saturating_add(1);
        self.expire(now);
        let result = self.ingest_inner(now, datagram);
        match &result {
            Ok(Some(packet)) => {
                self.stats.packets_completed = self.stats.packets_completed.saturating_add(1);
                self.stats.completed_bytes = self
                    .stats
                    .completed_bytes
                    .saturating_add(u64::try_from(packet.len()).unwrap_or(u64::MAX));
            }
            Ok(None) => {}
            Err(_) => {
                self.stats.fragments_rejected = self.stats.fragments_rejected.saturating_add(1);
            }
        }
        result
    }

    fn ingest_inner(
        &mut self,
        now: Instant,
        datagram: &[u8],
    ) -> Result<Option<Vec<u8>>, VpnPacketError> {
        let fragment = decode_vpn_ip_fragment(datagram)?;

        let mut partial = match self.packets.remove(&fragment.packet_id) {
            Some(partial) => {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(partial.received_bytes);
                partial
            }
            None => PartialPacket::new(fragment.total_len, now),
        };
        if partial.total_len != fragment.total_len {
            return Err(VpnPacketError::FragmentTotalChanged);
        }

        let fragment_end = fragment
            .offset
            .checked_add(fragment.payload.len())
            .ok_or(VpnPacketError::FragmentBounds)?;
        let mut duplicate = false;
        for (&existing_offset, existing_payload) in &partial.fragments {
            let existing_end = existing_offset + existing_payload.len();
            if existing_offset == fragment.offset && existing_payload.as_slice() == fragment.payload
            {
                duplicate = true;
                break;
            }
            if fragment.offset < existing_end && existing_offset < fragment_end {
                return Err(VpnPacketError::FragmentOverlap);
            }
        }

        if !duplicate {
            if partial.fragments.len() >= VPN_MAX_FRAGMENTS_PER_PACKET {
                return Err(VpnPacketError::FragmentLimitExceeded);
            }
            partial
                .fragments
                .insert(fragment.offset, fragment.payload.to_vec());
            partial.received_bytes = partial
                .received_bytes
                .checked_add(fragment.payload.len())
                .ok_or(VpnPacketError::FragmentBounds)?;
            partial.updated_at = now;
        } else {
            self.stats.duplicate_fragments = self.stats.duplicate_fragments.saturating_add(1);
        }

        if partial.received_bytes == partial.total_len {
            let mut packet = Vec::with_capacity(partial.total_len);
            for (offset, payload) in partial.fragments {
                if offset != packet.len() {
                    return Err(VpnPacketError::FragmentBounds);
                }
                packet.extend_from_slice(&payload);
            }
            if packet.len() != partial.total_len {
                return Err(VpnPacketError::FragmentBounds);
            }
            inspect_vpn_ip_packet(&packet)?;
            return Ok(Some(packet));
        }

        self.make_room(partial.received_bytes);
        self.buffered_bytes += partial.received_bytes;
        self.packets.insert(fragment.packet_id, partial);
        Ok(None)
    }

    fn make_room(&mut self, incoming_bytes: usize) {
        while self.packets.len() >= self.limits.max_inflight_packets {
            if !self.evict_oldest() {
                break;
            }
        }
        while self.buffered_bytes.saturating_add(incoming_bytes) > self.limits.max_buffered_bytes {
            if !self.evict_oldest() {
                break;
            }
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(packet_id) = self
            .packets
            .iter()
            .min_by_key(|(_, partial)| partial.updated_at)
            .map(|(&packet_id, _)| packet_id)
        else {
            return false;
        };
        self.remove_packet(packet_id);
        self.stats.packets_evicted = self.stats.packets_evicted.saturating_add(1);
        true
    }

    fn remove_packet(&mut self, packet_id: u32) {
        if let Some(partial) = self.packets.remove(&packet_id) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(partial.received_bytes);
        }
    }
}

impl Default for VpnReassembler {
    fn default() -> Self {
        Self::new(VpnReassemblyLimits::default()).expect("default VPN reassembly limits are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_ipv6_packet_inspection_is_strict() {
        let ipv4 = ipv4_packet(1500, 0x11);
        let meta = inspect_vpn_ip_packet(&ipv4).unwrap();
        assert_eq!(meta.source, "10.77.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(meta.destination, "1.1.1.1".parse::<IpAddr>().unwrap());

        let ipv6 = ipv6_packet(1280, 0x22);
        let meta = inspect_vpn_ip_packet(&ipv6).unwrap();
        assert_eq!(meta.source, "fd77::2".parse::<IpAddr>().unwrap());
        assert_eq!(
            meta.destination,
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
        );

        let mut bad_ipv4 = ipv4;
        bad_ipv4[3] = bad_ipv4[3].wrapping_sub(1);
        assert_eq!(
            inspect_vpn_ip_packet(&bad_ipv4).unwrap_err(),
            VpnPacketError::InvalidIpv4Length
        );

        let mut jumbogram = ipv6;
        jumbogram[4..6].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            inspect_vpn_ip_packet(&jumbogram).unwrap_err(),
            VpnPacketError::Ipv6JumbogramUnsupported
        );
    }

    #[test]
    fn fragments_roundtrip_out_of_order_and_ignore_exact_duplicates() {
        let packet = ipv4_packet(4096, 0x33);
        let mut fragments = encode_vpn_ip_fragments(7, &packet, 1100).unwrap();
        assert!(fragments.len() > 1);

        let now = Instant::now();
        let mut reassembler = VpnReassembler::default();
        assert!(reassembler.ingest(now, &fragments[0]).unwrap().is_none());
        assert!(reassembler.ingest(now, &fragments[0]).unwrap().is_none());

        fragments.remove(0);
        fragments.reverse();
        let mut completed = None;
        for fragment in fragments {
            completed = reassembler.ingest(now, &fragment).unwrap().or(completed);
        }
        assert_eq!(completed.unwrap(), packet);
        assert_eq!(reassembler.inflight_packets(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);
        assert_eq!(
            reassembler.stats(),
            VpnReassemblyStats {
                fragments_received: 5,
                duplicate_fragments: 1,
                packets_completed: 1,
                completed_bytes: packet.len() as u64,
                ..VpnReassemblyStats::default()
            }
        );
    }

    #[test]
    fn conflicting_overlap_discards_the_partial_packet() {
        let packet = ipv4_packet(2000, 0x44);
        let fragments = encode_vpn_ip_fragments(9, &packet, VPN_MIN_QUIC_DATAGRAM_LEN).unwrap();
        let now = Instant::now();
        let mut reassembler = VpnReassembler::default();
        reassembler.ingest(now, &fragments[0]).unwrap();

        let mut overlap = fragments[1].clone();
        overlap[10..12].copy_from_slice(&100_u16.to_be_bytes());
        assert_eq!(
            reassembler.ingest(now, &overlap).unwrap_err(),
            VpnPacketError::FragmentOverlap
        );
        assert_eq!(reassembler.inflight_packets(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn timeout_and_packet_capacity_bound_incomplete_state() {
        let limits = VpnReassemblyLimits {
            max_inflight_packets: 1,
            max_buffered_bytes: VPN_MAX_IP_PACKET_LEN,
            fragment_timeout: Duration::from_millis(10),
        };
        let mut reassembler = VpnReassembler::new(limits).unwrap();
        let first = encode_vpn_ip_fragments(1, &ipv4_packet(2000, 0x55), 1100).unwrap();
        let second = encode_vpn_ip_fragments(2, &ipv4_packet(2000, 0x66), 1100).unwrap();
        let now = Instant::now();
        reassembler.ingest(now, &first[0]).unwrap();
        reassembler.ingest(now, &second[0]).unwrap();
        assert_eq!(reassembler.inflight_packets(), 1);
        assert_eq!(reassembler.stats().packets_evicted, 1);
        assert_eq!(reassembler.expire(now + Duration::from_millis(11)), 1);
        assert_eq!(reassembler.inflight_packets(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);
        assert_eq!(reassembler.stats().packets_expired, 1);
    }

    #[test]
    fn duplicate_fragments_do_not_extend_the_reassembly_deadline() {
        let limits = VpnReassemblyLimits {
            max_inflight_packets: 2,
            max_buffered_bytes: VPN_MAX_IP_PACKET_LEN,
            fragment_timeout: Duration::from_millis(10),
        };
        let mut reassembler = VpnReassembler::new(limits).unwrap();
        let fragments = encode_vpn_ip_fragments(3, &ipv4_packet(2000, 0x77), 1100).unwrap();
        let now = Instant::now();
        reassembler.ingest(now, &fragments[0]).unwrap();
        reassembler
            .ingest(now + Duration::from_millis(9), &fragments[0])
            .unwrap();
        assert_eq!(reassembler.stats().duplicate_fragments, 1);
        assert_eq!(reassembler.expire(now + Duration::from_millis(11)), 1);
        assert_eq!(reassembler.inflight_packets(), 0);
    }

    #[test]
    fn all_packet_and_datagram_boundaries_roundtrip_with_at_most_sixty_four_fragments() {
        let packet_lengths = [20, 40, 1024, 1025, 1280, 1500, VPN_MAX_IP_PACKET_LEN];
        let datagram_lengths = [
            VPN_MIN_QUIC_DATAGRAM_LEN,
            1200,
            1450,
            VPN_IP_DATAGRAM_HEADER_LEN + VPN_MAX_IP_PACKET_LEN,
        ];
        for packet_len in packet_lengths {
            for max_datagram_len in datagram_lengths {
                let packet = ipv4_packet(packet_len, 0x88);
                let mut fragments =
                    encode_vpn_ip_fragments(packet_len as u32, &packet, max_datagram_len).unwrap();
                assert!(!fragments.is_empty());
                assert!(fragments.len() <= VPN_MAX_FRAGMENTS_PER_PACKET);
                assert!(
                    fragments
                        .iter()
                        .all(|fragment| fragment.len() <= max_datagram_len)
                );
                fragments.reverse();
                let mut reassembler = VpnReassembler::default();
                let mut completed = None;
                for fragment in fragments {
                    completed = reassembler
                        .ingest(Instant::now(), &fragment)
                        .unwrap()
                        .or(completed);
                }
                assert_eq!(completed.unwrap(), packet);
                assert_eq!(reassembler.inflight_packets(), 0);
                assert_eq!(reassembler.buffered_bytes(), 0);
            }
        }
    }

    #[test]
    fn deterministic_malformed_input_preserves_all_resource_bounds_without_panics() {
        let limits = VpnReassemblyLimits {
            max_inflight_packets: 8,
            max_buffered_bytes: VPN_MAX_IP_PACKET_LEN * 2,
            fragment_timeout: Duration::from_millis(25),
        };
        let mut reassembler = VpnReassembler::new(limits).unwrap();
        let started = Instant::now();
        let mut state = 0x4D59_5DF4_D0F3_3173_u64;
        for sequence in 0..20_000_u64 {
            state = xorshift64(state);
            let len = usize::try_from(state % 2048).unwrap();
            let mut datagram = vec![0_u8; len];
            for byte in &mut datagram {
                state = xorshift64(state);
                *byte = state as u8;
            }
            if sequence % 3 == 0 && datagram.len() > VPN_IP_DATAGRAM_HEADER_LEN {
                datagram[..4].copy_from_slice(VPN_IP_DATAGRAM_MAGIC);
                datagram[4..8].copy_from_slice(&(state as u32).to_be_bytes());
                let payload_len = datagram.len() - VPN_IP_DATAGRAM_HEADER_LEN;
                let total_len = u16::try_from(payload_len + 1).unwrap();
                datagram[8..10].copy_from_slice(&total_len.to_be_bytes());
                datagram[10..12].copy_from_slice(&0_u16.to_be_bytes());
            }
            let now = started + Duration::from_millis(sequence / 50);
            let _ = decode_vpn_ip_fragment(&datagram);
            let _ = inspect_vpn_ip_packet(&datagram);
            let _ = reassembler.ingest(now, &datagram);
            assert!(reassembler.inflight_packets() <= limits.max_inflight_packets);
            assert!(reassembler.buffered_bytes() <= limits.max_buffered_bytes);
        }
        assert_eq!(reassembler.stats().fragments_received, 20_000);
        assert!(reassembler.stats().fragments_rejected > 0);
        assert!(reassembler.stats().packets_evicted > 0);
    }

    #[test]
    fn malformed_fragment_headers_are_rejected_before_reassembly() {
        assert_eq!(
            decode_vpn_ip_fragment(b"FWI1").unwrap_err(),
            VpnPacketError::FragmentEmpty
        );
        let mut datagram = vec![0_u8; VPN_IP_DATAGRAM_HEADER_LEN + 1];
        datagram[..4].copy_from_slice(b"BAD1");
        assert_eq!(
            decode_vpn_ip_fragment(&datagram).unwrap_err(),
            VpnPacketError::InvalidMagic
        );
        datagram[..4].copy_from_slice(VPN_IP_DATAGRAM_MAGIC);
        datagram[8..10].copy_from_slice(&1_u16.to_be_bytes());
        datagram[10..12].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_vpn_ip_fragment(&datagram).unwrap_err(),
            VpnPacketError::FragmentBounds
        );

        for foreign_magic in [b"FWI0", b"FWI2"] {
            datagram[..4].copy_from_slice(foreign_magic);
            assert_eq!(
                decode_vpn_ip_fragment(&datagram).unwrap_err(),
                VpnPacketError::InvalidMagic,
                "未知 VPN 版本不得被当成 FWI1 猜测解析"
            );
        }
        assert_eq!(
            encode_vpn_ip_fragments(1, &ipv4_packet(1280, 0x99), VPN_MIN_QUIC_DATAGRAM_LEN - 1,)
                .unwrap_err(),
            VpnPacketError::DatagramCapacityTooSmall
        );
    }

    fn ipv4_packet(len: usize, fill: u8) -> Vec<u8> {
        assert!((20..=VPN_MAX_IP_PACKET_LEN).contains(&len));
        let mut packet = vec![fill; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 77, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet
    }

    fn ipv6_packet(len: usize, fill: u8) -> Vec<u8> {
        assert!((40..=VPN_MAX_IP_PACKET_LEN).contains(&len));
        let mut packet = vec![fill; len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"fd77::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40]
            .copy_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        packet
    }

    fn xorshift64(mut value: u64) -> u64 {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        value
    }
}
