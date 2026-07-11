use std::{
    ffi::{c_int, c_void},
    io,
    mem::{align_of, size_of},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::fd::AsRawFd,
    ptr, thread,
    time::{Duration, Instant},
};

use crate::LabResult;

const PROBE_MAGIC: &[u8; 4] = b"FWCP";
const PROBE_HEADER_BYTES: usize = 9;
const IPV4_UDP_HEADER_BYTES: usize = 28;
const MIN_PACKET_COUNT: usize = 8;
const MAX_PACKET_COUNT: usize = 128;
const MIN_PAYLOAD_BYTES: usize = 64;
const MAX_PAYLOAD_BYTES: usize = 1_472;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);
const TIMESTAMP_BATCH_THRESHOLD: Duration = Duration::from_micros(30);
const MIN_CHIRP_QUEUE_SIGNAL_SECONDS: f64 = 50e-6;
const MAX_NORMALIZED_FIT_ERROR: f64 = 0.35;
const MAX_PACKET_TRAIN_GAP_CV: f64 = 0.35;
const CHIRP_SEARCH_STEPS: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapacityProbeMethod {
    PacketTrain,
    Chirp {
        initial_rate_mbps: f64,
        spread_factor: f64,
    },
}

impl CapacityProbeMethod {
    pub fn description(self) -> &'static str {
        match self {
            Self::PacketTrain => "背靠背 Packet Train",
            Self::Chirp { .. } => "Chirp 排队曲线拟合",
        }
    }

    fn wire_id(self) -> u8 {
        match self {
            Self::PacketTrain => 1,
            Self::Chirp { .. } => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CapacityProbeConfig {
    pub source_ip: Ipv4Addr,
    pub receiver_ip: Ipv4Addr,
    pub method: CapacityProbeMethod,
    pub packet_count: usize,
    pub payload_bytes: usize,
}

impl CapacityProbeConfig {
    pub fn packet_train(source_ip: Ipv4Addr, receiver_ip: Ipv4Addr) -> Self {
        Self {
            source_ip,
            receiver_ip,
            method: CapacityProbeMethod::PacketTrain,
            packet_count: 16,
            payload_bytes: 1_200,
        }
    }

    pub fn chirp(source_ip: Ipv4Addr, receiver_ip: Ipv4Addr) -> Self {
        Self {
            source_ip,
            receiver_ip,
            method: CapacityProbeMethod::Chirp {
                initial_rate_mbps: 2.0,
                spread_factor: 1.25,
            },
            packet_count: 16,
            payload_bytes: 1_200,
        }
    }

    pub fn estimated_wire_bytes(self) -> usize {
        self.packet_count
            .saturating_mul(self.payload_bytes.saturating_add(IPV4_UDP_HEADER_BYTES))
    }

    fn validate(self) -> LabResult<()> {
        if !(MIN_PACKET_COUNT..=MAX_PACKET_COUNT).contains(&self.packet_count) {
            return Err(io::Error::other(format!(
                "容量探针包数必须在 {MIN_PACKET_COUNT} 到 {MAX_PACKET_COUNT} 之间"
            ))
            .into());
        }
        if !(MIN_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&self.payload_bytes) {
            return Err(io::Error::other(format!(
                "容量探针 UDP 载荷必须在 {MIN_PAYLOAD_BYTES} 到 {MAX_PAYLOAD_BYTES} 字节之间"
            ))
            .into());
        }
        if self.payload_bytes < PROBE_HEADER_BYTES {
            return Err(io::Error::other("容量探针载荷放不下固定头部").into());
        }
        if self.source_ip == self.receiver_ip {
            return Err(io::Error::other("容量探针发送地址与接收地址不能相同").into());
        }
        if let CapacityProbeMethod::Chirp {
            initial_rate_mbps,
            spread_factor,
        } = self.method
        {
            if !initial_rate_mbps.is_finite() || initial_rate_mbps <= 0.0 {
                return Err(io::Error::other("Chirp 初始速率必须是正数").into());
            }
            if !spread_factor.is_finite() || spread_factor <= 1.0 {
                return Err(io::Error::other("Chirp 相邻速率倍率必须大于 1").into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CapacityProbeReport {
    pub method: CapacityProbeMethod,
    pub estimated_mbps: Option<f64>,
    pub usable: bool,
    pub rejection_reason: Option<String>,
    pub sent_packets: usize,
    pub received_packets: usize,
    pub timestamped_packets: usize,
    pub missing_receive_timestamps: usize,
    pub lost_packets: usize,
    pub payload_bytes_sent: usize,
    pub estimated_wire_bytes_sent: usize,
    pub elapsed: Duration,
    pub timestamp_anomalies: usize,
    pub maximum_consecutive_timestamp_anomalies: usize,
    pub out_of_order_packets: usize,
    pub fit_rmse_us: Option<f64>,
    pub normalized_fit_error: Option<f64>,
    pub queue_signal_us: Option<f64>,
    pub packet_train_gap_cv: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct ReceivedPacket {
    sequence: usize,
    received_at_seconds: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct ChirpEstimate {
    mbps: f64,
    fit_rmse_seconds: f64,
    normalized_fit_error: f64,
    queue_signal_seconds: f64,
    hit_search_boundary: bool,
}

pub fn run_local_capacity_probe(config: CapacityProbeConfig) -> LabResult<CapacityProbeReport> {
    config.validate()?;

    let receiver = UdpSocket::bind(SocketAddrV4::new(config.receiver_ip, 0))?;
    receiver.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
    enable_kernel_receive_timestamps(&receiver)?;
    let receiver_addr = receiver.local_addr()?;

    let sender = UdpSocket::bind(SocketAddrV4::new(config.source_ip, 0))?;
    let receive_method = config.method;
    let expected_packets = config.packet_count;
    let receiver_task = thread::Builder::new()
        .name("flowweave-capacity-probe-receiver".to_owned())
        .spawn(move || receive_packets(receiver, receive_method, expected_packets))?;

    let started_at = Instant::now();
    let send_offsets = send_packets(&sender, receiver_addr, config)?;
    let received = receiver_task
        .join()
        .map_err(|_| io::Error::other("容量探针接收线程异常退出"))??;
    let elapsed = started_at.elapsed();

    Ok(analyze_probe(config, &send_offsets, &received, elapsed))
}

fn send_packets(
    sender: &UdpSocket,
    receiver_addr: std::net::SocketAddr,
    config: CapacityProbeConfig,
) -> LabResult<Vec<f64>> {
    let mut payload = vec![0_u8; config.payload_bytes];
    payload[..4].copy_from_slice(PROBE_MAGIC);
    payload[8] = config.method.wire_id();
    for (index, byte) in payload[PROBE_HEADER_BYTES..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(31).wrapping_add(17);
    }

    let wire_bits = wire_bytes(config.payload_bytes) as f64 * 8.0;
    let planned_gaps = planned_send_gaps(config.method, config.packet_count, wire_bits);
    let schedule_start = Instant::now();
    let mut deadline = schedule_start;
    let mut send_offsets = Vec::with_capacity(config.packet_count);

    for sequence in 0..config.packet_count {
        if sequence > 0 {
            deadline += planned_gaps[sequence - 1];
            wait_until(deadline);
        }

        payload[4..8].copy_from_slice(&(sequence as u32).to_be_bytes());
        let before = Instant::now();
        let sent = sender.send_to(&payload, receiver_addr)?;
        let after = Instant::now();
        if sent != payload.len() {
            return Err(io::Error::other("容量探针 UDP 包没有完整发送").into());
        }
        let send_time = before + after.saturating_duration_since(before) / 2;
        send_offsets.push(
            send_time
                .saturating_duration_since(schedule_start)
                .as_secs_f64(),
        );
    }

    Ok(send_offsets)
}

fn receive_packets(
    receiver: UdpSocket,
    method: CapacityProbeMethod,
    expected_packets: usize,
) -> io::Result<Vec<ReceivedPacket>> {
    let mut buffer = vec![0_u8; MAX_PAYLOAD_BYTES];
    let mut received: Vec<ReceivedPacket> = Vec::with_capacity(expected_packets);

    loop {
        match recv_with_kernel_timestamp(&receiver, &mut buffer) {
            Ok((length, received_at_seconds)) => {
                if length < PROBE_HEADER_BYTES
                    || &buffer[..4] != PROBE_MAGIC
                    || buffer[8] != method.wire_id()
                {
                    continue;
                }
                let sequence =
                    u32::from_be_bytes(buffer[4..8].try_into().expect("容量探针编号固定为 4 字节"))
                        as usize;
                if sequence >= expected_packets
                    || received.iter().any(|packet| packet.sequence == sequence)
                {
                    continue;
                }
                received.push(ReceivedPacket {
                    sequence,
                    received_at_seconds,
                });
                if received.len() == expected_packets {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(received)
}

fn analyze_probe(
    config: CapacityProbeConfig,
    send_offsets: &[f64],
    received: &[ReceivedPacket],
    elapsed: Duration,
) -> CapacityProbeReport {
    let received_packets = received.len();
    let timestamped_packets = received
        .iter()
        .filter(|packet| packet.received_at_seconds.is_some())
        .count();
    let missing_receive_timestamps = received_packets.saturating_sub(timestamped_packets);
    let lost_packets = config.packet_count.saturating_sub(received_packets);
    let (timestamp_anomalies, maximum_consecutive_timestamp_anomalies) =
        timestamp_anomalies(received);
    let out_of_order_packets = received
        .windows(2)
        .filter(|pair| pair[1].sequence < pair[0].sequence)
        .count();
    let receive_offsets = receive_offsets_by_sequence(config.packet_count, received);
    let wire_bytes = wire_bytes(config.payload_bytes);

    let mut estimated_mbps = None;
    let mut fit_rmse_us = None;
    let mut normalized_fit_error = None;
    let mut queue_signal_us = None;
    let mut packet_train_gap_cv = None;
    let mut method_rejection = None;

    match config.method {
        CapacityProbeMethod::PacketTrain => {
            if let Some((estimate, gap_cv)) = estimate_packet_train(&receive_offsets, wire_bytes) {
                estimated_mbps = Some(estimate);
                packet_train_gap_cv = Some(gap_cv);
                if gap_cv > MAX_PACKET_TRAIN_GAP_CV {
                    method_rejection = Some(format!(
                        "包间隔波动系数 {gap_cv:.3} 超过 {MAX_PACKET_TRAIN_GAP_CV:.2}"
                    ));
                }
            } else {
                method_rejection = Some("Packet Train 有效时间戳不足".to_owned());
            }
        }
        CapacityProbeMethod::Chirp {
            initial_rate_mbps,
            spread_factor,
        } => {
            if let Some(estimate) = estimate_chirp(
                send_offsets,
                &receive_offsets,
                wire_bytes,
                initial_rate_mbps,
                spread_factor,
            ) {
                estimated_mbps = Some(estimate.mbps);
                fit_rmse_us = Some(estimate.fit_rmse_seconds * 1_000_000.0);
                normalized_fit_error = Some(estimate.normalized_fit_error);
                queue_signal_us = Some(estimate.queue_signal_seconds * 1_000_000.0);
                if estimate.hit_search_boundary {
                    method_rejection =
                        Some("Chirp 最优值落在搜索边界，探测速率范围不足".to_owned());
                } else if estimate.queue_signal_seconds < MIN_CHIRP_QUEUE_SIGNAL_SECONDS {
                    method_rejection = Some(format!(
                        "Chirp 排队信号不足 {:.1} 微秒",
                        MIN_CHIRP_QUEUE_SIGNAL_SECONDS * 1_000_000.0
                    ));
                } else if estimate.normalized_fit_error > MAX_NORMALIZED_FIT_ERROR {
                    method_rejection = Some(format!(
                        "Chirp 归一化拟合误差 {:.3} 超过 {MAX_NORMALIZED_FIT_ERROR:.2}",
                        estimate.normalized_fit_error
                    ));
                }
            } else {
                method_rejection = Some("Chirp 有效时间戳不足".to_owned());
            }
        }
    }

    let common_rejection = if received_packets * 4 < config.packet_count * 3 {
        Some(format!(
            "只收到 {received_packets}/{} 个探针包",
            config.packet_count
        ))
    } else if timestamped_packets * 4 < config.packet_count * 3 {
        Some(format!(
            "只有 {timestamped_packets}/{} 个包带内核接收时间戳",
            config.packet_count
        ))
    } else if out_of_order_packets > 0 {
        Some(format!("检测到 {out_of_order_packets} 个乱序探针包"))
    } else if maximum_consecutive_timestamp_anomalies >= 2 {
        Some("检测到连续内核接收时间戳批处理，本轮包间隔不可信".to_owned())
    } else {
        None
    };
    let rejection_reason = common_rejection.or(method_rejection);

    CapacityProbeReport {
        method: config.method,
        estimated_mbps,
        usable: rejection_reason.is_none() && estimated_mbps.is_some(),
        rejection_reason,
        sent_packets: config.packet_count,
        received_packets,
        timestamped_packets,
        missing_receive_timestamps,
        lost_packets,
        payload_bytes_sent: config.packet_count.saturating_mul(config.payload_bytes),
        estimated_wire_bytes_sent: config.estimated_wire_bytes(),
        elapsed,
        timestamp_anomalies,
        maximum_consecutive_timestamp_anomalies,
        out_of_order_packets,
        fit_rmse_us,
        normalized_fit_error,
        queue_signal_us,
        packet_train_gap_cv,
    }
}

fn planned_send_gaps(
    method: CapacityProbeMethod,
    packet_count: usize,
    wire_bits: f64,
) -> Vec<Duration> {
    match method {
        CapacityProbeMethod::PacketTrain => vec![Duration::ZERO; packet_count - 1],
        CapacityProbeMethod::Chirp {
            initial_rate_mbps,
            spread_factor,
        } => (0..packet_count - 1)
            .map(|index| {
                let rate_bps = initial_rate_mbps * 1_000_000.0 * spread_factor.powi(index as i32);
                Duration::from_secs_f64(wire_bits / rate_bps)
            })
            .collect(),
    }
}

fn wait_until(deadline: Instant) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let remaining = deadline.saturating_duration_since(now);
        if remaining > Duration::from_micros(250) {
            thread::sleep(remaining - Duration::from_micros(150));
        } else {
            std::hint::spin_loop();
        }
    }
}

fn receive_offsets_by_sequence(
    packet_count: usize,
    received: &[ReceivedPacket],
) -> Vec<Option<f64>> {
    let Some(origin) = received
        .iter()
        .filter_map(|packet| packet.received_at_seconds)
        .min_by(f64::total_cmp)
    else {
        return vec![None; packet_count];
    };
    let mut offsets = vec![None; packet_count];
    for packet in received {
        offsets[packet.sequence] = packet
            .received_at_seconds
            .map(|timestamp| timestamp - origin);
    }
    offsets
}

fn timestamp_anomalies(received: &[ReceivedPacket]) -> (usize, usize) {
    let mut anomalies = 0;
    let mut consecutive = 0;
    let mut maximum_consecutive = 0;

    let mut previous = None;
    for packet in received {
        let Some(timestamp) = packet.received_at_seconds else {
            previous = None;
            consecutive = 0;
            continue;
        };
        if previous
            .is_some_and(|previous| timestamp - previous < TIMESTAMP_BATCH_THRESHOLD.as_secs_f64())
        {
            anomalies += 1;
            consecutive += 1;
            maximum_consecutive = maximum_consecutive.max(consecutive);
        } else {
            consecutive = 0;
        }
        previous = Some(timestamp);
    }

    (anomalies, maximum_consecutive)
}

fn estimate_packet_train(receive_offsets: &[Option<f64>], wire_bytes: usize) -> Option<(f64, f64)> {
    let received: Vec<_> = receive_offsets
        .iter()
        .enumerate()
        .filter_map(|(sequence, offset)| offset.map(|offset| (sequence, offset)))
        .collect();
    let (first_sequence, first_offset) = *received.first()?;
    let (last_sequence, last_offset) = *received.last()?;
    let packet_intervals = last_sequence.checked_sub(first_sequence)?;
    let span = last_offset - first_offset;
    if packet_intervals == 0 || span <= 0.0 {
        return None;
    }

    let estimated_mbps = packet_intervals as f64 * wire_bytes as f64 * 8.0 / span / 1_000_000.0;
    let normalized_gaps: Vec<_> = received
        .windows(2)
        .filter_map(|pair| {
            let sequence_gap = pair[1].0.checked_sub(pair[0].0)?;
            let time_gap = pair[1].1 - pair[0].1;
            (sequence_gap > 0 && time_gap > 0.0).then_some(time_gap / sequence_gap as f64)
        })
        .collect();
    let gap_cv = coefficient_of_variation(&normalized_gaps)?;
    Some((estimated_mbps, gap_cv))
}

fn estimate_chirp(
    send_offsets: &[f64],
    receive_offsets: &[Option<f64>],
    wire_bytes: usize,
    initial_rate_mbps: f64,
    spread_factor: f64,
) -> Option<ChirpEstimate> {
    if send_offsets.len() != receive_offsets.len() || send_offsets.len() < MIN_PACKET_COUNT {
        return None;
    }
    let observed_indices: Vec<_> = receive_offsets
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.map(|value| (index, value)))
        .collect();
    if observed_indices.len() * 4 < send_offsets.len() * 3 {
        return None;
    }
    let (base_index, base_receive) = *observed_indices.first()?;
    let base_send = send_offsets[base_index];
    let observed_queue: Vec<_> = observed_indices
        .iter()
        .map(|(index, receive)| {
            (
                *index,
                (*receive - base_receive) - (send_offsets[*index] - base_send),
            )
        })
        .collect();
    let observed_min = observed_queue
        .iter()
        .map(|(_, value)| *value)
        .min_by(f64::total_cmp)?;
    let observed_max = observed_queue
        .iter()
        .map(|(_, value)| *value)
        .max_by(f64::total_cmp)?;
    let queue_signal_seconds = observed_max - observed_min;

    let last_gap_index = send_offsets.len().saturating_sub(2) as i32;
    let maximum_probe_rate = initial_rate_mbps * spread_factor.powi(last_gap_index);
    let search_min = initial_rate_mbps * 0.5;
    let search_max = maximum_probe_rate * 2.0;
    let search_step = (search_max - search_min) / CHIRP_SEARCH_STEPS as f64;
    let wire_bits = wire_bytes as f64 * 8.0;

    let mut best_rate = search_min;
    let mut best_mse = f64::INFINITY;
    let mut best_index = 0;
    for candidate_index in 0..=CHIRP_SEARCH_STEPS {
        let candidate_rate = search_min + candidate_index as f64 * search_step;
        let predicted = predicted_queue(send_offsets, wire_bits, candidate_rate);
        let predicted_base = predicted[base_index];
        let mse = observed_queue
            .iter()
            .map(|(index, observed)| {
                let residual = observed - (predicted[*index] - predicted_base);
                residual * residual
            })
            .sum::<f64>()
            / observed_queue.len() as f64;
        if mse < best_mse {
            best_mse = mse;
            best_rate = candidate_rate;
            best_index = candidate_index;
        }
    }

    let fit_rmse_seconds = best_mse.sqrt();
    let normalized_fit_error = fit_rmse_seconds / queue_signal_seconds.max(1e-9);
    Some(ChirpEstimate {
        mbps: best_rate,
        fit_rmse_seconds,
        normalized_fit_error,
        queue_signal_seconds,
        hit_search_boundary: best_index == 0 || best_index == CHIRP_SEARCH_STEPS,
    })
}

fn predicted_queue(send_offsets: &[f64], wire_bits: f64, candidate_mbps: f64) -> Vec<f64> {
    let service_seconds = wire_bits / (candidate_mbps * 1_000_000.0);
    let mut queue = vec![0.0; send_offsets.len()];
    for index in 1..send_offsets.len() {
        let send_gap = send_offsets[index] - send_offsets[index - 1];
        queue[index] = (queue[index - 1] + service_seconds - send_gap).max(0.0);
    }
    queue
}

fn coefficient_of_variation(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let variance = values
        .iter()
        .map(|value| {
            let difference = value - mean;
            difference * difference
        })
        .sum::<f64>()
        / values.len() as f64;
    Some(variance.sqrt() / mean)
}

const fn wire_bytes(payload_bytes: usize) -> usize {
    payload_bytes + IPV4_UDP_HEADER_BYTES
}

#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const SO_TIMESTAMPNS: c_int = 35;
#[cfg(all(target_os = "linux", target_pointer_width = "32"))]
const SO_TIMESTAMPNS: c_int = 64;

#[cfg(target_os = "linux")]
#[repr(C)]
struct IoVector {
    base: *mut c_void,
    length: usize,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct MessageHeader {
    name: *mut c_void,
    name_length: u32,
    vectors: *mut IoVector,
    vector_count: usize,
    control: *mut c_void,
    control_length: usize,
    flags: c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ControlMessageHeader {
    length: usize,
    level: c_int,
    kind: c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelTimespec {
    seconds: i64,
    nanoseconds: i64,
}

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct ControlBuffer([u8; 128]);

#[cfg(target_os = "linux")]
unsafe extern "C" {
    #[link_name = "setsockopt"]
    fn system_setsockopt(
        socket: c_int,
        level: c_int,
        option: c_int,
        value: *const c_void,
        value_length: u32,
    ) -> c_int;

    #[link_name = "recvmsg"]
    fn system_recvmsg(socket: c_int, message: *mut MessageHeader, flags: c_int) -> isize;
}

#[cfg(target_os = "linux")]
fn enable_kernel_receive_timestamps(socket: &UdpSocket) -> io::Result<()> {
    let enabled: c_int = 1;
    // SAFETY: socket 是仍然存活的 UDP 文件描述符；value 指向长度正确的 c_int。
    let result = unsafe {
        system_setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_TIMESTAMPNS,
            ptr::from_ref(&enabled).cast(),
            size_of::<c_int>() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_kernel_receive_timestamps(_socket: &UdpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "容量探针的内核接收时间戳实验目前只支持 Linux",
    ))
}

#[cfg(target_os = "linux")]
fn recv_with_kernel_timestamp(
    socket: &UdpSocket,
    payload: &mut [u8],
) -> io::Result<(usize, Option<f64>)> {
    let mut vector = IoVector {
        base: payload.as_mut_ptr().cast(),
        length: payload.len(),
    };
    let mut control = ControlBuffer([0_u8; 128]);
    let mut message = MessageHeader {
        name: ptr::null_mut(),
        name_length: 0,
        vectors: ptr::from_mut(&mut vector),
        vector_count: 1,
        control: control.0.as_mut_ptr().cast(),
        control_length: control.0.len(),
        flags: 0,
    };

    // SAFETY: MessageHeader、IoVector 和两个缓冲区在调用期间均有效且可写，长度与实际分配一致。
    let received = unsafe { system_recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    let control_length = message.control_length.min(control.0.len());
    let timestamp = parse_kernel_timestamp(&control.0[..control_length]);
    Ok((received as usize, timestamp))
}

#[cfg(not(target_os = "linux"))]
fn recv_with_kernel_timestamp(
    _socket: &UdpSocket,
    _payload: &mut [u8],
) -> io::Result<(usize, Option<f64>)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "容量探针的内核接收时间戳实验目前只支持 Linux",
    ))
}

#[cfg(target_os = "linux")]
fn parse_kernel_timestamp(control: &[u8]) -> Option<f64> {
    let header_size = size_of::<ControlMessageHeader>();
    let data_offset = align_cmsg(header_size);
    let mut offset = 0;

    while offset + header_size <= control.len() {
        // SAFETY: 边界检查保证 ControlMessageHeader 的全部字节都在 control 内；
        // 控制消息内部不保证 Rust 对齐，因此使用 read_unaligned。
        let header = unsafe {
            ptr::read_unaligned(control.as_ptr().add(offset).cast::<ControlMessageHeader>())
        };
        if header.length < data_offset || offset + header.length > control.len() {
            return None;
        }
        if header.level == SOL_SOCKET
            && header.kind == SO_TIMESTAMPNS
            && header.length >= data_offset + size_of::<KernelTimespec>()
        {
            // SAFETY: cmsg 长度检查保证 KernelTimespec 完整位于当前控制消息内。
            let timestamp = unsafe {
                ptr::read_unaligned(
                    control
                        .as_ptr()
                        .add(offset + data_offset)
                        .cast::<KernelTimespec>(),
                )
            };
            if timestamp.seconds >= 0 && (0..1_000_000_000).contains(&timestamp.nanoseconds) {
                return Some(timestamp.seconds as f64 + timestamp.nanoseconds as f64 / 1e9);
            }
            return None;
        }

        let next = align_cmsg(header.length);
        if next == 0 {
            return None;
        }
        offset = offset.saturating_add(next);
    }
    None
}

#[cfg(target_os = "linux")]
const fn align_cmsg(length: usize) -> usize {
    let alignment = align_of::<usize>();
    (length + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_receive_offsets(
        send_offsets: &[f64],
        wire_bytes: usize,
        capacity_mbps: f64,
    ) -> Vec<Option<f64>> {
        let queue = predicted_queue(send_offsets, wire_bytes as f64 * 8.0, capacity_mbps);
        send_offsets
            .iter()
            .zip(queue)
            .map(|(send, queue)| Some(send + 0.020 + queue))
            .collect()
    }

    #[test]
    fn packet_train_recovers_synthetic_capacity_with_one_missing_timestamp() {
        let wire_bytes = 1_228;
        let spacing = wire_bytes as f64 * 8.0 / 8_000_000.0;
        let mut receive_offsets: Vec<_> =
            (0..16).map(|index| Some(index as f64 * spacing)).collect();
        receive_offsets[7] = None;

        let (estimate, gap_cv) = estimate_packet_train(&receive_offsets, wire_bytes).unwrap();
        assert!((estimate - 8.0).abs() < 0.001);
        assert!(gap_cv < 0.001);
    }

    #[test]
    fn chirp_curve_fit_distinguishes_eight_and_twenty_five_mbps() {
        let config =
            CapacityProbeConfig::chirp(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 3));
        let CapacityProbeMethod::Chirp {
            initial_rate_mbps,
            spread_factor,
        } = config.method
        else {
            unreachable!();
        };
        let wire_bytes = wire_bytes(config.payload_bytes);
        let gaps = planned_send_gaps(config.method, config.packet_count, wire_bytes as f64 * 8.0);
        let mut send_offsets = vec![0.0];
        for gap in gaps {
            send_offsets.push(send_offsets.last().unwrap() + gap.as_secs_f64());
        }

        for expected in [8.0, 25.0] {
            let receive_offsets = synthetic_receive_offsets(&send_offsets, wire_bytes, expected);
            let estimate = estimate_chirp(
                &send_offsets,
                &receive_offsets,
                wire_bytes,
                initial_rate_mbps,
                spread_factor,
            )
            .unwrap();
            assert!((estimate.mbps - expected).abs() / expected < 0.01);
            assert!(estimate.normalized_fit_error < 0.01);
            assert!(!estimate.hit_search_boundary);
        }
    }

    #[test]
    fn chirp_without_self_induced_queue_hits_search_boundary() {
        let config =
            CapacityProbeConfig::chirp(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 3));
        let CapacityProbeMethod::Chirp {
            initial_rate_mbps,
            spread_factor,
        } = config.method
        else {
            unreachable!();
        };
        let wire_bytes = wire_bytes(config.payload_bytes);
        let gaps = planned_send_gaps(config.method, config.packet_count, wire_bytes as f64 * 8.0);
        let mut send_offsets = vec![0.0];
        for gap in gaps {
            send_offsets.push(send_offsets.last().unwrap() + gap.as_secs_f64());
        }
        let receive_offsets: Vec<_> = send_offsets
            .iter()
            .map(|offset| Some(offset + 0.020))
            .collect();

        let estimate = estimate_chirp(
            &send_offsets,
            &receive_offsets,
            wire_bytes,
            initial_rate_mbps,
            spread_factor,
        )
        .unwrap();
        assert!(estimate.hit_search_boundary || estimate.queue_signal_seconds < 1e-9);
    }

    #[test]
    fn invalid_probe_configuration_is_rejected() {
        let mut config = CapacityProbeConfig::packet_train(
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 3),
        );
        config.packet_count = 1;
        assert!(config.validate().is_err());

        config.packet_count = 16;
        config.source_ip = config.receiver_ip;
        assert!(config.validate().is_err());
    }
}
