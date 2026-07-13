use std::{
    array,
    fmt::Write as _,
    fs,
    io::{self, BufRead, BufReader, Write as IoWrite},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{LabError, LabResult};

const RESULT_PATH_V1: &str =
    "benchmark-results/2026-07-13-b-separated-ingress-observability-v1-smoke.csv";
const RESULT_PATH_V2: &str =
    "benchmark-results/2026-07-13-b-separated-ingress-observability-v2-smoke.csv";
const WIRE_MAGIC: &[u8; 4] = b"FWBI";
const WIRE_VERSION: u8 = 1;
const HEADER_BYTES: usize = 16;
const PAYLOAD_BYTES: usize = 1_200;
const IPV4_UDP_HEADER_BYTES: usize = 28;
const ESTIMATED_WIRE_BYTES: usize = PAYLOAD_BYTES + IPV4_UDP_HEADER_BYTES;
const WARMUP: Duration = Duration::from_secs(1);
const MEASUREMENT: Duration = Duration::from_secs(2);
const PHASE_COOLDOWN: Duration = Duration::from_millis(400);
const RECEIVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const RECEIVE_TIMEOUT: Duration = Duration::from_millis(100);
const LINE_ONE_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 241, 1, 1);
const LINE_ONE_RECEIVER: Ipv4Addr = Ipv4Addr::new(10, 241, 1, 2);
const LINE_TWO_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 241, 2, 1);
const LINE_TWO_RECEIVER: Ipv4Addr = Ipv4Addr::new(10, 241, 2, 2);
const LINE_ONE_PORT: u16 = 46_101;
const LINE_TWO_PRIMARY_PORT: u16 = 46_102;
const LINE_TWO_CROSS_PORT: u16 = 46_103;
const LINE_ONE_RECEIVER_INTERFACE: &str = "fwbr1";
const LINE_TWO_RECEIVER_INTERFACE: &str = "fwbr2";
const PHASE_COUNT: usize = 3;
const FLOW_COUNT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    ApplicationLimited,
    LineLimited,
    CrossTraffic,
}

impl Phase {
    const ALL: [Self; PHASE_COUNT] = [
        Self::ApplicationLimited,
        Self::LineLimited,
        Self::CrossTraffic,
    ];

    const fn id(self) -> u8 {
        match self {
            Self::ApplicationLimited => 1,
            Self::LineLimited => 2,
            Self::CrossTraffic => 3,
        }
    }

    const fn index(self) -> usize {
        self.id() as usize - 1
    }

    const fn description(self) -> &'static str {
        match self {
            Self::ApplicationLimited => "application-limited",
            Self::LineLimited => "line-limited",
            Self::CrossTraffic => "cross-traffic",
        }
    }

    fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|phase| phase.id() == id)
    }

    fn flow_specs(self) -> Vec<FlowSpec> {
        match self {
            Self::ApplicationLimited => {
                vec![FlowSpec::line_one(4.0), FlowSpec::line_two_primary(12.5)]
            }
            Self::LineLimited => vec![FlowSpec::line_one(12.0), FlowSpec::line_two_primary(37.5)],
            Self::CrossTraffic => vec![
                FlowSpec::line_two_primary(10.0),
                FlowSpec::line_two_cross(25.0),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowId {
    PrimaryOne,
    PrimaryTwo,
    CrossTwo,
}

impl FlowId {
    const fn id(self) -> u8 {
        match self {
            Self::PrimaryOne => 1,
            Self::PrimaryTwo => 2,
            Self::CrossTwo => 3,
        }
    }

    const fn index(self) -> usize {
        self.id() as usize - 1
    }
}

#[derive(Debug, Clone, Copy)]
struct FlowSpec {
    flow: FlowId,
    source_ip: Ipv4Addr,
    receiver_ip: Ipv4Addr,
    receiver_port: u16,
    target_mbps: f64,
}

impl FlowSpec {
    const fn line_one(target_mbps: f64) -> Self {
        Self {
            flow: FlowId::PrimaryOne,
            source_ip: LINE_ONE_SOURCE,
            receiver_ip: LINE_ONE_RECEIVER,
            receiver_port: LINE_ONE_PORT,
            target_mbps,
        }
    }

    const fn line_two_primary(target_mbps: f64) -> Self {
        Self {
            flow: FlowId::PrimaryTwo,
            source_ip: LINE_TWO_SOURCE,
            receiver_ip: LINE_TWO_RECEIVER,
            receiver_port: LINE_TWO_PRIMARY_PORT,
            target_mbps,
        }
    }

    const fn line_two_cross(target_mbps: f64) -> Self {
        Self {
            flow: FlowId::CrossTwo,
            source_ip: LINE_TWO_SOURCE,
            receiver_ip: LINE_TWO_RECEIVER,
            receiver_port: LINE_TWO_CROSS_PORT,
            target_mbps,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct InterfaceStats {
    rx_bytes: u64,
    rx_packets: u64,
}

impl InterfaceStats {
    fn delta(self, before: Self) -> Self {
        Self {
            rx_bytes: self.rx_bytes.saturating_sub(before.rx_bytes),
            rx_packets: self.rx_packets.saturating_sub(before.rx_packets),
        }
    }
}

struct ReceiverCounters {
    packets: [[AtomicU64; FLOW_COUNT]; PHASE_COUNT],
    payload_bytes: [[AtomicU64; FLOW_COUNT]; PHASE_COUNT],
    malformed_packets: AtomicU64,
    source_error_packets: AtomicU64,
    content_error_packets: AtomicU64,
    unknown_phase_packets: AtomicU64,
}

impl ReceiverCounters {
    fn new() -> Self {
        Self {
            packets: array::from_fn(|_| array::from_fn(|_| AtomicU64::new(0))),
            payload_bytes: array::from_fn(|_| array::from_fn(|_| AtomicU64::new(0))),
            malformed_packets: AtomicU64::new(0),
            source_error_packets: AtomicU64::new(0),
            content_error_packets: AtomicU64::new(0),
            unknown_phase_packets: AtomicU64::new(0),
        }
    }

    fn snapshot(&self, phase: Phase) -> ReceiverCounterSnapshot {
        ReceiverCounterSnapshot {
            packets: array::from_fn(|index| {
                self.packets[phase.index()][index].load(Ordering::Relaxed)
            }),
            payload_bytes: array::from_fn(|index| {
                self.payload_bytes[phase.index()][index].load(Ordering::Relaxed)
            }),
            malformed_packets: self.malformed_packets.load(Ordering::Relaxed),
            source_error_packets: self.source_error_packets.load(Ordering::Relaxed),
            content_error_packets: self.content_error_packets.load(Ordering::Relaxed),
            unknown_phase_packets: self.unknown_phase_packets.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ReceiverCounterSnapshot {
    packets: [u64; FLOW_COUNT],
    payload_bytes: [u64; FLOW_COUNT],
    malformed_packets: u64,
    source_error_packets: u64,
    content_error_packets: u64,
    unknown_phase_packets: u64,
}

impl ReceiverCounterSnapshot {
    fn delta(self, before: Self) -> Self {
        Self {
            packets: array::from_fn(|index| {
                self.packets[index].saturating_sub(before.packets[index])
            }),
            payload_bytes: array::from_fn(|index| {
                self.payload_bytes[index].saturating_sub(before.payload_bytes[index])
            }),
            malformed_packets: self
                .malformed_packets
                .saturating_sub(before.malformed_packets),
            source_error_packets: self
                .source_error_packets
                .saturating_sub(before.source_error_packets),
            content_error_packets: self
                .content_error_packets
                .saturating_sub(before.content_error_packets),
            unknown_phase_packets: self
                .unknown_phase_packets
                .saturating_sub(before.unknown_phase_packets),
        }
    }

    const fn total_errors(self) -> u64 {
        self.malformed_packets
            + self.source_error_packets
            + self.content_error_packets
            + self.unknown_phase_packets
    }
}

#[derive(Debug, Clone, Copy)]
struct ReceiverPhaseReport {
    phase: Phase,
    elapsed: Duration,
    line_one: InterfaceStats,
    line_two: InterfaceStats,
    counters: ReceiverCounterSnapshot,
}

#[derive(Debug)]
struct SenderHandle {
    stop: Arc<AtomicBool>,
    sent_packets: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl SenderHandle {
    fn start(spec: FlowSpec, phase: Phase) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let sent_packets = Arc::new(AtomicU64::new(0));
        let send_errors = Arc::new(AtomicU64::new(0));
        let task_stop = stop.clone();
        let task_sent = sent_packets.clone();
        let task_errors = send_errors.clone();
        let task = thread::Builder::new()
            .name(format!("flowweave-b-ingress-sender-{}", spec.flow.id()))
            .spawn(move || run_paced_sender(spec, phase, task_stop, task_sent, task_errors))?;
        Ok(Self {
            stop,
            sent_packets,
            send_errors,
            task: Some(task),
        })
    }

    fn packets(&self) -> u64 {
        self.sent_packets.load(Ordering::Relaxed)
    }

    fn errors(&self) -> u64 {
        self.send_errors.load(Ordering::Relaxed)
    }

    fn stop_and_join(mut self) -> LabResult<()> {
        self.stop.store(true, Ordering::Relaxed);
        let task = self
            .task
            .take()
            .ok_or_else(|| other_error("B ingress sender task missing"))?;
        task.join()
            .map_err(|_| other_error("B ingress sender thread panicked"))??;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PhaseObservation {
    phase: Phase,
    elapsed: Duration,
    target_mbps: [f64; FLOW_COUNT],
    offered_packets: [u64; FLOW_COUNT],
    sender_errors: u64,
    receiver: ReceiverPhaseReport,
    namespace_separated: bool,
    accounting_pass: bool,
    phase_pass: bool,
}

impl PhaseObservation {
    fn offered_mbps(&self, flow: FlowId) -> f64 {
        mbps_from_packets(self.offered_packets[flow.index()], self.elapsed)
    }

    fn received_mbps(&self, flow: FlowId) -> f64 {
        mbps_from_packets(self.receiver.counters.packets[flow.index()], self.elapsed)
    }

    fn line_one_ingress_mbps(&self) -> f64 {
        mbps_from_bytes(self.receiver.line_one.rx_bytes, self.elapsed)
    }

    fn line_two_ingress_mbps(&self) -> f64 {
        mbps_from_bytes(self.receiver.line_two.rx_bytes, self.elapsed)
    }
}

#[derive(Debug, Clone)]
pub struct BIngressSmokeReport {
    pub sender_netns: String,
    pub receiver_netns: String,
    pub phases_completed: usize,
    pub total_sender_errors: u64,
    pub total_receiver_errors: u64,
    pub cpu_time: Duration,
    pub cpu_utilization_percent: f64,
    pub controller_peak_rss_kib: u64,
    pub receiver_peak_rss_kib: u64,
    pub stage_pass: bool,
}

struct ReceiverProcess {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<io::Result<String>>,
    reader_task: Option<JoinHandle<()>>,
}

impl ReceiverProcess {
    fn spawn(receiver_pid: u32) -> LabResult<Self> {
        let executable = std::env::current_exe()?;
        let mut child = Command::new("nsenter")
            .args(["-t", &receiver_pid.to_string(), "-n", "--"])
            .arg(executable)
            .arg("receiver")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| other_error("B ingress receiver stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| other_error("B ingress receiver stdout unavailable"))?;
        let (tx, lines) = mpsc::channel();
        let reader_task = thread::Builder::new()
            .name("flowweave-b-ingress-receiver-output".to_owned())
            .spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            child,
            stdin,
            lines,
            reader_task: Some(reader_task),
        })
    }

    fn send_command(&mut self, command: &str) -> LabResult<()> {
        writeln!(self.stdin, "{command}")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn receive_line(&self, expected_prefix: &str) -> LabResult<String> {
        let line = self
            .lines
            .recv_timeout(RECEIVER_COMMAND_TIMEOUT)
            .map_err(|_| {
                other_error(format!("等待 B ingress receiver {expected_prefix} 超时"))
            })??;
        if !line.starts_with(expected_prefix) {
            return Err(other_error(format!(
                "B ingress receiver 返回意外行，期望 {expected_prefix}，实际 {line}"
            )));
        }
        Ok(line)
    }

    fn finish(mut self) -> LabResult<()> {
        self.send_command("QUIT")?;
        let _ = self.receive_line("BYE");
        let status = self.child.wait()?;
        if let Some(task) = self.reader_task.take() {
            task.join()
                .map_err(|_| other_error("B ingress receiver output thread panicked"))?;
        }
        if !status.success() {
            return Err(other_error(format!(
                "B ingress receiver exited with {status}"
            )));
        }
        Ok(())
    }
}

impl Drop for ReceiverProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn run_b_ingress_observability_controller(receiver_pid: u32) -> LabResult<BIngressSmokeReport> {
    verify_controller_environment(receiver_pid)?;
    let result_path = selected_result_path()?;
    ensure_result_absent(result_path)?;
    write_observations(result_path, &[], None)?;

    let sender_netns = read_netns_identity("/proc/self/ns/net")?;
    let parent_netns = std::env::var("FLOWWEAVE_PARENT_NETNS")?;
    let expected_receiver_netns = read_netns_identity(format!("/proc/{receiver_pid}/ns/net"))?;
    let namespace_separated = sender_netns != parent_netns
        && sender_netns != expected_receiver_netns
        && parent_netns != expected_receiver_netns;
    if !namespace_separated {
        return Err(other_error("B ingress 三个网络命名空间没有正确分离"));
    }

    let ticks_per_second = process_clock_ticks_per_second()?;
    let cpu_before = read_process_cpu_ticks(std::process::id())?;
    let wall_started = Instant::now();
    let mut receiver = ReceiverProcess::spawn(receiver_pid)?;
    let ready = receiver.receive_line("READY ")?;
    let receiver_netns = parse_text_field(&ready, "receiver_ns")?;
    if receiver_netns != expected_receiver_netns {
        return Err(other_error(format!(
            "B ingress receiver namespace changed: expected {expected_receiver_netns}, got {receiver_netns}"
        )));
    }
    let receiver_process_pid = receiver.child.id();
    let receiver_cpu_before = read_process_cpu_ticks(receiver_process_pid)?;

    let mut observations = Vec::with_capacity(PHASE_COUNT);
    for phase in Phase::ALL {
        let observation = run_phase(&mut receiver, phase, namespace_separated)?;
        observations.push(observation);
        write_observations(result_path, &observations, None)?;
        thread::sleep(PHASE_COOLDOWN);
    }

    let receiver_cpu_after = read_process_cpu_ticks(receiver_process_pid)?;
    let receiver_peak_rss_kib = read_peak_rss_kib(receiver_process_pid)?;
    receiver.finish()?;
    let cpu_after = read_process_cpu_ticks(std::process::id())?;
    let cpu_ticks = cpu_after
        .saturating_sub(cpu_before)
        .saturating_add(receiver_cpu_after.saturating_sub(receiver_cpu_before));
    let cpu_time = Duration::from_secs_f64(cpu_ticks as f64 / ticks_per_second as f64);
    let wall_elapsed = wall_started.elapsed();
    let cpu_utilization_percent = if wall_elapsed.is_zero() {
        0.0
    } else {
        cpu_time.as_secs_f64() / wall_elapsed.as_secs_f64() * 100.0
    };
    let controller_peak_rss_kib = read_peak_rss_kib(std::process::id())?;
    let total_sender_errors = observations
        .iter()
        .map(|observation| observation.sender_errors)
        .sum();
    let total_receiver_errors = observations
        .iter()
        .map(|observation| observation.receiver.counters.total_errors())
        .sum();
    let stage_pass = observations.len() == PHASE_COUNT
        && namespace_separated
        && total_sender_errors == 0
        && total_receiver_errors == 0
        && observations
            .iter()
            .all(|observation| observation.phase_pass);

    let report = BIngressSmokeReport {
        sender_netns,
        receiver_netns,
        phases_completed: observations.len(),
        total_sender_errors,
        total_receiver_errors,
        cpu_time,
        cpu_utilization_percent,
        controller_peak_rss_kib,
        receiver_peak_rss_kib,
        stage_pass,
    };
    write_observations(result_path, &observations, Some(&report))?;
    print_observations(&observations, &report, result_path);
    Ok(report)
}

pub fn run_b_ingress_shaper_calibration(receiver_pid: u32) -> LabResult<()> {
    verify_controller_environment(receiver_pid)?;
    let sender_netns = read_netns_identity("/proc/self/ns/net")?;
    let parent_netns = std::env::var("FLOWWEAVE_PARENT_NETNS")?;
    let receiver_netns = read_netns_identity(format!("/proc/{receiver_pid}/ns/net"))?;
    let namespace_separated = sender_netns != parent_netns
        && sender_netns != receiver_netns
        && parent_netns != receiver_netns;
    if !namespace_separated {
        return Err(other_error(
            "B ingress calibration network namespaces are not separated",
        ));
    }

    let mut receiver = ReceiverProcess::spawn(receiver_pid)?;
    let ready = receiver.receive_line("READY ")?;
    if parse_text_field(&ready, "receiver_ns")? != receiver_netns {
        return Err(other_error(
            "B ingress calibration receiver namespace changed",
        ));
    }
    let observation = run_phase(&mut receiver, Phase::LineLimited, namespace_separated)?;
    receiver.finish()?;
    println!(
        "CALIBRATION line_one_ingress_mbps={:.6} line_two_ingress_mbps={:.6} line_one_offered_mbps={:.6} line_two_offered_mbps={:.6} line_one_rx_packets={} line_two_rx_packets={}",
        observation.line_one_ingress_mbps(),
        observation.line_two_ingress_mbps(),
        observation.offered_mbps(FlowId::PrimaryOne),
        observation.offered_mbps(FlowId::PrimaryTwo),
        observation.receiver.line_one.rx_packets,
        observation.receiver.line_two.rx_packets,
    );
    Ok(())
}

fn run_phase(
    receiver: &mut ReceiverProcess,
    phase: Phase,
    namespace_separated: bool,
) -> LabResult<PhaseObservation> {
    let specs = phase.flow_specs();
    let mut senders = Vec::with_capacity(specs.len());
    for spec in &specs {
        senders.push((*spec, SenderHandle::start(*spec, phase)?));
    }
    thread::sleep(WARMUP);

    receiver.send_command(&format!("START {}", phase.id()))?;
    let started = receiver.receive_line("STARTED ")?;
    if parse_u64_field(&started, "phase")? != phase.id() as u64 {
        return Err(other_error("B ingress receiver started wrong phase"));
    }
    let sent_before: Vec<_> = senders.iter().map(|(_, sender)| sender.packets()).collect();
    let errors_before: Vec<_> = senders.iter().map(|(_, sender)| sender.errors()).collect();
    let measurement_started = Instant::now();
    thread::sleep(MEASUREMENT);
    let elapsed = measurement_started.elapsed();
    let sent_after: Vec<_> = senders.iter().map(|(_, sender)| sender.packets()).collect();
    let errors_after: Vec<_> = senders.iter().map(|(_, sender)| sender.errors()).collect();

    receiver.send_command(&format!("STOP {}", phase.id()))?;
    let receiver_report = parse_receiver_report(&receiver.receive_line("REPORT ")?)?;
    if receiver_report.phase != phase {
        return Err(other_error("B ingress receiver stopped wrong phase"));
    }
    for (_, sender) in senders.drain(..) {
        sender.stop_and_join()?;
    }

    let mut target_mbps = [0.0; FLOW_COUNT];
    let mut offered_packets = [0_u64; FLOW_COUNT];
    let mut sender_errors = 0_u64;
    for (index, spec) in specs.iter().enumerate() {
        target_mbps[spec.flow.index()] = spec.target_mbps;
        offered_packets[spec.flow.index()] = sent_after[index].saturating_sub(sent_before[index]);
        sender_errors =
            sender_errors.saturating_add(errors_after[index].saturating_sub(errors_before[index]));
    }
    let mut observation = PhaseObservation {
        phase,
        elapsed,
        target_mbps,
        offered_packets,
        sender_errors,
        receiver: receiver_report,
        namespace_separated,
        accounting_pass: false,
        phase_pass: false,
    };
    observation.accounting_pass = accounting_pass(&observation);
    observation.phase_pass = phase_gate(&observation);
    Ok(observation)
}

fn accounting_pass(observation: &PhaseObservation) -> bool {
    let line_one_app = observation.received_mbps(FlowId::PrimaryOne);
    let line_two_app =
        observation.received_mbps(FlowId::PrimaryTwo) + observation.received_mbps(FlowId::CrossTwo);
    let line_one_ingress = observation.line_one_ingress_mbps();
    let line_two_ingress = observation.line_two_ingress_mbps();
    let line_one_ok = if line_one_ingress < 0.01 {
        line_one_app < 0.01
    } else {
        relative_error(line_one_app, line_one_ingress) <= 0.10
    };
    let line_two_ok = if line_two_ingress < 0.01 {
        line_two_app < 0.01
    } else {
        relative_error(line_two_app, line_two_ingress) <= 0.10
    };
    line_one_ok && line_two_ok
}

fn phase_gate(observation: &PhaseObservation) -> bool {
    let safe = observation.namespace_separated
        && observation.sender_errors == 0
        && observation.receiver.counters.total_errors() == 0
        && observation.accounting_pass;
    if !safe {
        return false;
    }
    let line_one_ingress = observation.line_one_ingress_mbps();
    let line_two_ingress = observation.line_two_ingress_mbps();
    match observation.phase {
        Phase::ApplicationLimited => {
            within_fraction(line_one_ingress, 4.0, 0.10)
                && within_fraction(line_two_ingress, 12.5, 0.10)
                && line_one_ingress < 8.0 * 0.75
                && line_two_ingress < 25.0 * 0.75
                && within_fraction(observation.offered_mbps(FlowId::PrimaryOne), 4.0, 0.05)
                && within_fraction(observation.offered_mbps(FlowId::PrimaryTwo), 12.5, 0.05)
        }
        Phase::LineLimited => {
            let ratio = line_two_ingress / line_one_ingress.max(f64::EPSILON);
            within_fraction(line_one_ingress, 8.0, 0.10)
                && within_fraction(line_two_ingress, 25.0, 0.10)
                && within_fraction(ratio, 25.0 / 8.0, 0.10)
                && observation.offered_mbps(FlowId::PrimaryOne) >= 8.0 * 1.25
                && observation.offered_mbps(FlowId::PrimaryTwo) >= 25.0 * 1.25
        }
        Phase::CrossTraffic => {
            let primary = observation.received_mbps(FlowId::PrimaryTwo);
            let cross = observation.received_mbps(FlowId::CrossTwo);
            line_one_ingress < 0.1
                && within_fraction(line_two_ingress, 25.0, 0.10)
                && primary <= line_two_ingress * 0.75
                && cross > 0.1
                && within_fraction(observation.offered_mbps(FlowId::PrimaryTwo), 10.0, 0.05)
                && within_fraction(observation.offered_mbps(FlowId::CrossTwo), 25.0, 0.05)
        }
    }
}

fn run_paced_sender(
    spec: FlowSpec,
    phase: Phase,
    stop: Arc<AtomicBool>,
    sent_packets: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(spec.source_ip, 0))?;
    socket.connect(SocketAddrV4::new(spec.receiver_ip, spec.receiver_port))?;
    let mut payload = [0_u8; PAYLOAD_BYTES];
    payload[..4].copy_from_slice(WIRE_MAGIC);
    payload[4] = WIRE_VERSION;
    payload[5] = phase.id();
    payload[6] = spec.flow.id();
    for (index, byte) in payload[HEADER_BYTES..].iter_mut().enumerate() {
        *byte = expected_payload_byte(index);
    }

    let interval = Duration::from_secs_f64(
        ESTIMATED_WIRE_BYTES as f64 * 8.0 / (spec.target_mbps * 1_000_000.0),
    );
    let mut sequence = 0_u64;
    let mut deadline = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        deadline += interval;
        wait_until(deadline);
        payload[8..16].copy_from_slice(&sequence.to_be_bytes());
        match socket.send(&payload) {
            Ok(length) if length == PAYLOAD_BYTES => {
                sent_packets.fetch_add(1, Ordering::Relaxed);
            }
            Ok(_) => {
                send_errors.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                send_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        sequence = sequence.wrapping_add(1);
    }
    Ok(())
}

fn wait_until(deadline: Instant) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let remaining = deadline.saturating_duration_since(now);
        if remaining > Duration::from_micros(200) {
            thread::sleep(remaining - Duration::from_micros(100));
        } else {
            std::hint::spin_loop();
        }
    }
}

pub fn run_b_ingress_observability_receiver() -> LabResult<()> {
    let running = Arc::new(AtomicBool::new(true));
    let counters = Arc::new(ReceiverCounters::new());
    let workers = vec![
        spawn_receiver_worker(
            LINE_ONE_RECEIVER,
            LINE_ONE_PORT,
            LINE_ONE_SOURCE,
            FlowId::PrimaryOne,
            running.clone(),
            counters.clone(),
        )?,
        spawn_receiver_worker(
            LINE_TWO_RECEIVER,
            LINE_TWO_PRIMARY_PORT,
            LINE_TWO_SOURCE,
            FlowId::PrimaryTwo,
            running.clone(),
            counters.clone(),
        )?,
        spawn_receiver_worker(
            LINE_TWO_RECEIVER,
            LINE_TWO_CROSS_PORT,
            LINE_TWO_SOURCE,
            FlowId::CrossTwo,
            running.clone(),
            counters.clone(),
        )?,
    ];

    let receiver_netns = read_netns_identity("/proc/self/ns/net")?;
    println!("READY receiver_ns={receiver_netns}");
    io::stdout().flush()?;
    let mut active: Option<(
        Phase,
        Instant,
        InterfaceStats,
        InterfaceStats,
        ReceiverCounterSnapshot,
    )> = None;

    for line in io::stdin().lock().lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("START") => {
                if active.is_some() {
                    return Err(other_error(
                        "B ingress receiver already has an active phase",
                    ));
                }
                let phase = parse_phase_field(fields.next())?;
                let line_one = read_interface_stats(LINE_ONE_RECEIVER_INTERFACE)?;
                let line_two = read_interface_stats(LINE_TWO_RECEIVER_INTERFACE)?;
                active = Some((
                    phase,
                    Instant::now(),
                    line_one,
                    line_two,
                    counters.snapshot(phase),
                ));
                println!("STARTED phase={}", phase.id());
                io::stdout().flush()?;
            }
            Some("STOP") => {
                let requested = parse_phase_field(fields.next())?;
                let (phase, started, line_one_before, line_two_before, counters_before) = active
                    .take()
                    .ok_or_else(|| other_error("B ingress receiver has no active phase"))?;
                if phase != requested {
                    return Err(other_error("B ingress receiver STOP phase mismatch"));
                }
                let elapsed = started.elapsed();
                let line_one =
                    read_interface_stats(LINE_ONE_RECEIVER_INTERFACE)?.delta(line_one_before);
                let line_two =
                    read_interface_stats(LINE_TWO_RECEIVER_INTERFACE)?.delta(line_two_before);
                let snapshot = counters.snapshot(phase).delta(counters_before);
                println!(
                    "REPORT phase={} elapsed_us={} line_one_rx_bytes={} line_one_rx_packets={} line_two_rx_bytes={} line_two_rx_packets={} flow_one_packets={} flow_one_payload_bytes={} flow_two_primary_packets={} flow_two_primary_payload_bytes={} flow_two_cross_packets={} flow_two_cross_payload_bytes={} malformed={} source_errors={} content_errors={} unknown_phase={}",
                    phase.id(),
                    elapsed.as_micros(),
                    line_one.rx_bytes,
                    line_one.rx_packets,
                    line_two.rx_bytes,
                    line_two.rx_packets,
                    snapshot.packets[FlowId::PrimaryOne.index()],
                    snapshot.payload_bytes[FlowId::PrimaryOne.index()],
                    snapshot.packets[FlowId::PrimaryTwo.index()],
                    snapshot.payload_bytes[FlowId::PrimaryTwo.index()],
                    snapshot.packets[FlowId::CrossTwo.index()],
                    snapshot.payload_bytes[FlowId::CrossTwo.index()],
                    snapshot.malformed_packets,
                    snapshot.source_error_packets,
                    snapshot.content_error_packets,
                    snapshot.unknown_phase_packets,
                );
                io::stdout().flush()?;
            }
            Some("QUIT") => {
                println!("BYE");
                io::stdout().flush()?;
                break;
            }
            Some(command) => {
                return Err(other_error(format!(
                    "B ingress receiver unknown command {command}"
                )));
            }
            None => {}
        }
    }

    running.store(false, Ordering::Relaxed);
    for worker in workers {
        worker
            .join()
            .map_err(|_| other_error("B ingress receiver worker panicked"))??;
    }
    Ok(())
}

fn spawn_receiver_worker(
    bind_ip: Ipv4Addr,
    port: u16,
    expected_source: Ipv4Addr,
    expected_flow: FlowId,
    running: Arc<AtomicBool>,
    counters: Arc<ReceiverCounters>,
) -> io::Result<JoinHandle<io::Result<()>>> {
    let socket = UdpSocket::bind(SocketAddrV4::new(bind_ip, port))?;
    socket.set_read_timeout(Some(RECEIVE_TIMEOUT))?;
    thread::Builder::new()
        .name(format!(
            "flowweave-b-ingress-receiver-{}",
            expected_flow.id()
        ))
        .spawn(move || {
            let mut payload = [0_u8; PAYLOAD_BYTES];
            while running.load(Ordering::Relaxed) {
                match socket.recv_from(&mut payload) {
                    Ok((length, source)) => {
                        if length != PAYLOAD_BYTES
                            || payload[..4] != *WIRE_MAGIC
                            || payload[4] != WIRE_VERSION
                            || payload[6] != expected_flow.id()
                        {
                            counters.malformed_packets.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if source.ip() != expected_source {
                            counters
                                .source_error_packets
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let Some(phase) = Phase::from_id(payload[5]) else {
                            counters
                                .unknown_phase_packets
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        if payload[HEADER_BYTES..]
                            .iter()
                            .enumerate()
                            .any(|(index, byte)| *byte != expected_payload_byte(index))
                        {
                            counters
                                .content_error_packets
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        counters.packets[phase.index()][expected_flow.index()]
                            .fetch_add(1, Ordering::Relaxed);
                        counters.payload_bytes[phase.index()][expected_flow.index()]
                            .fetch_add(length as u64, Ordering::Relaxed);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
}

const fn expected_payload_byte(index: usize) -> u8 {
    (index as u8).wrapping_mul(31).wrapping_add(17)
}

fn parse_receiver_report(line: &str) -> LabResult<ReceiverPhaseReport> {
    let phase_id = parse_u64_field(line, "phase")?;
    let phase = Phase::from_id(
        u8::try_from(phase_id).map_err(|_| other_error("B ingress phase id out of range"))?,
    )
    .ok_or_else(|| other_error("B ingress receiver reported unknown phase"))?;
    let elapsed_micros = parse_u64_field(line, "elapsed_us")?;
    Ok(ReceiverPhaseReport {
        phase,
        elapsed: Duration::from_micros(elapsed_micros),
        line_one: InterfaceStats {
            rx_bytes: parse_u64_field(line, "line_one_rx_bytes")?,
            rx_packets: parse_u64_field(line, "line_one_rx_packets")?,
        },
        line_two: InterfaceStats {
            rx_bytes: parse_u64_field(line, "line_two_rx_bytes")?,
            rx_packets: parse_u64_field(line, "line_two_rx_packets")?,
        },
        counters: ReceiverCounterSnapshot {
            packets: [
                parse_u64_field(line, "flow_one_packets")?,
                parse_u64_field(line, "flow_two_primary_packets")?,
                parse_u64_field(line, "flow_two_cross_packets")?,
            ],
            payload_bytes: [
                parse_u64_field(line, "flow_one_payload_bytes")?,
                parse_u64_field(line, "flow_two_primary_payload_bytes")?,
                parse_u64_field(line, "flow_two_cross_payload_bytes")?,
            ],
            malformed_packets: parse_u64_field(line, "malformed")?,
            source_error_packets: parse_u64_field(line, "source_errors")?,
            content_error_packets: parse_u64_field(line, "content_errors")?,
            unknown_phase_packets: parse_u64_field(line, "unknown_phase")?,
        },
    })
}

fn parse_phase_field(value: Option<&str>) -> LabResult<Phase> {
    let value = value.ok_or_else(|| other_error("B ingress phase id missing"))?;
    let id = value.parse::<u8>()?;
    Phase::from_id(id).ok_or_else(|| other_error(format!("unknown B ingress phase {id}")))
}

fn parse_u64_field(line: &str, name: &str) -> LabResult<u64> {
    let value = find_field(line, name)?;
    Ok(value.parse::<u64>()?)
}

fn parse_text_field(line: &str, name: &str) -> LabResult<String> {
    Ok(find_field(line, name)?.to_owned())
}

fn find_field<'a>(line: &'a str, name: &str) -> LabResult<&'a str> {
    line.split_whitespace()
        .find_map(|field| field.split_once('=').filter(|(key, _)| *key == name))
        .map(|(_, value)| value)
        .ok_or_else(|| other_error(format!("B ingress field {name} missing from {line}")))
}

fn read_interface_stats(interface: &str) -> LabResult<InterfaceStats> {
    let contents = fs::read_to_string("/proc/net/dev")?;
    for line in contents.lines() {
        let Some((name, fields)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != interface {
            continue;
        }
        let mut fields = fields.split_whitespace();
        let rx_bytes = fields
            .next()
            .ok_or_else(|| other_error("B ingress rx_bytes missing"))?
            .parse()?;
        let rx_packets = fields
            .next()
            .ok_or_else(|| other_error("B ingress rx_packets missing"))?
            .parse()?;
        return Ok(InterfaceStats {
            rx_bytes,
            rx_packets,
        });
    }
    Err(other_error(format!(
        "B ingress interface {interface} missing from /proc/net/dev"
    )))
}

fn verify_controller_environment(receiver_pid: u32) -> LabResult<()> {
    if std::env::var("FLOWWEAVE_B_INGRESS_LAB").as_deref() != Ok("1") {
        return Err(other_error(
            "B ingress observability must run through scripts/run_b_ingress_lab.sh",
        ));
    }
    let uid_map = fs::read_to_string("/proc/self/uid_map")?;
    let mapped_as_root = uid_map
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        == Some("0");
    if !mapped_as_root {
        return Err(other_error("B ingress lab is not rootless-mapped as uid 0"));
    }
    if receiver_pid == 0 || !Path::new(&format!("/proc/{receiver_pid}/ns/net")).exists() {
        return Err(other_error(
            "B ingress receiver namespace holder is unavailable",
        ));
    }
    Ok(())
}

fn read_netns_identity(path: impl AsRef<Path>) -> LabResult<String> {
    Ok(fs::read_link(path)?.to_string_lossy().into_owned())
}

fn ensure_result_absent(path: &str) -> LabResult<()> {
    if Path::new(path).exists() {
        return Err(other_error(format!(
            "refusing to overwrite historical B ingress result {path}"
        )));
    }
    Ok(())
}

fn write_observations(
    path: &str,
    observations: &[PhaseObservation],
    report: Option<&BIngressSmokeReport>,
) -> LabResult<()> {
    let mut csv = String::from(
        "phase,sender_netns,receiver_netns,line_one_seed,line_two_seed,measurement_ms,line_one_target_mbps,line_two_primary_target_mbps,line_two_cross_target_mbps,line_one_offered_mbps,line_two_primary_offered_mbps,line_two_cross_offered_mbps,line_one_ingress_mbps,line_two_ingress_mbps,line_one_received_mbps,line_two_primary_received_mbps,line_two_cross_received_mbps,line_one_rx_bytes,line_two_rx_bytes,line_one_rx_packets,line_two_rx_packets,line_one_sent_packets,line_two_primary_sent_packets,line_two_cross_sent_packets,line_one_received_packets,line_two_primary_received_packets,line_two_cross_received_packets,sender_errors,receiver_errors,namespace_separated,accounting_pass,phase_pass,cpu_time_ms,cpu_utilization_percent,controller_peak_rss_kib,receiver_peak_rss_kib,stage_pass\n",
    );
    let sender_netns = report.map_or("", |report| report.sender_netns.as_str());
    let receiver_netns = report.map_or("", |report| report.receiver_netns.as_str());
    let cpu_time_ms = report.map_or(0.0, |report| report.cpu_time.as_secs_f64() * 1_000.0);
    let cpu_utilization = report.map_or(0.0, |report| report.cpu_utilization_percent);
    let controller_rss = report.map_or(0, |report| report.controller_peak_rss_kib);
    let receiver_rss = report.map_or(0, |report| report.receiver_peak_rss_kib);
    let stage_pass = report.is_some_and(|report| report.stage_pass);
    for observation in observations {
        writeln!(
            csv,
            "{},{},{},1101,2201,{:.3},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.3},{:.6},{},{},{}",
            observation.phase.description(),
            sender_netns,
            receiver_netns,
            observation.receiver.elapsed.as_secs_f64() * 1_000.0,
            observation.target_mbps[FlowId::PrimaryOne.index()],
            observation.target_mbps[FlowId::PrimaryTwo.index()],
            observation.target_mbps[FlowId::CrossTwo.index()],
            observation.offered_mbps(FlowId::PrimaryOne),
            observation.offered_mbps(FlowId::PrimaryTwo),
            observation.offered_mbps(FlowId::CrossTwo),
            observation.line_one_ingress_mbps(),
            observation.line_two_ingress_mbps(),
            observation.received_mbps(FlowId::PrimaryOne),
            observation.received_mbps(FlowId::PrimaryTwo),
            observation.received_mbps(FlowId::CrossTwo),
            observation.receiver.line_one.rx_bytes,
            observation.receiver.line_two.rx_bytes,
            observation.receiver.line_one.rx_packets,
            observation.receiver.line_two.rx_packets,
            observation.offered_packets[FlowId::PrimaryOne.index()],
            observation.offered_packets[FlowId::PrimaryTwo.index()],
            observation.offered_packets[FlowId::CrossTwo.index()],
            observation.receiver.counters.packets[FlowId::PrimaryOne.index()],
            observation.receiver.counters.packets[FlowId::PrimaryTwo.index()],
            observation.receiver.counters.packets[FlowId::CrossTwo.index()],
            observation.sender_errors,
            observation.receiver.counters.total_errors(),
            observation.namespace_separated,
            observation.accounting_pass,
            observation.phase_pass,
            cpu_time_ms,
            cpu_utilization,
            controller_rss,
            receiver_rss,
            stage_pass,
        )?;
    }
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, csv)?;
    Ok(())
}

fn print_observations(
    observations: &[PhaseObservation],
    report: &BIngressSmokeReport,
    result_path: &str,
) {
    println!();
    println!(
        "FlowWeave / 织流：B 组分离 veth ingress 可观测场 {}",
        if result_path == RESULT_PATH_V2 {
            "v2"
        } else {
            "v1"
        }
    );
    for observation in observations {
        println!(
            "- {}：offered {:.3}/{:.3}/{:.3} Mbit/s；ingress {:.3}/{:.3}；received {:.3}/{:.3}/{:.3}；accounting {}；phase {}",
            observation.phase.description(),
            observation.offered_mbps(FlowId::PrimaryOne),
            observation.offered_mbps(FlowId::PrimaryTwo),
            observation.offered_mbps(FlowId::CrossTwo),
            observation.line_one_ingress_mbps(),
            observation.line_two_ingress_mbps(),
            observation.received_mbps(FlowId::PrimaryOne),
            observation.received_mbps(FlowId::PrimaryTwo),
            observation.received_mbps(FlowId::CrossTwo),
            if observation.accounting_pass {
                "通过"
            } else {
                "失败"
            },
            if observation.phase_pass {
                "通过"
            } else {
                "失败"
            },
        );
    }
    println!(
        "- namespaces sender={} receiver={}；sender errors {} receiver errors {}；CPU {:.3} ms / {:.3}%；RSS controller/receiver {}/{} KiB；stage {}",
        report.sender_netns,
        report.receiver_netns,
        report.total_sender_errors,
        report.total_receiver_errors,
        report.cpu_time.as_secs_f64() * 1_000.0,
        report.cpu_utilization_percent,
        report.controller_peak_rss_kib,
        report.receiver_peak_rss_kib,
        if report.stage_pass {
            "通过"
        } else {
            "失败"
        },
    );
    println!("- 原始数据：{result_path}");
}

fn selected_result_path() -> LabResult<&'static str> {
    match std::env::var("FLOWWEAVE_B_INGRESS_VERSION").as_deref() {
        Ok("v1") => Ok(RESULT_PATH_V1),
        Ok("v2") => Ok(RESULT_PATH_V2),
        Ok(version) => Err(other_error(format!(
            "unknown B ingress observability version {version}"
        ))),
        Err(_) => Err(other_error("B ingress observability version is missing")),
    }
}

fn mbps_from_packets(packets: u64, elapsed: Duration) -> f64 {
    mbps_from_bytes(packets.saturating_mul(ESTIMATED_WIRE_BYTES as u64), elapsed)
}

fn mbps_from_bytes(bytes: u64, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        return 0.0;
    }
    bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
}

fn relative_error(value: f64, expected: f64) -> f64 {
    if expected.abs() < f64::EPSILON {
        return value.abs();
    }
    (value / expected - 1.0).abs()
}

fn within_fraction(value: f64, expected: f64, tolerance: f64) -> bool {
    value.is_finite() && relative_error(value, expected) <= tolerance
}

fn process_clock_ticks_per_second() -> LabResult<u64> {
    let output = Command::new("getconf").arg("CLK_TCK").output()?;
    if !output.status.success() {
        return Err(other_error("getconf CLK_TCK failed"));
    }
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

fn read_process_cpu_ticks(pid: u32) -> LabResult<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_name = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| other_error("invalid /proc stat"))?;
    let fields: Vec<_> = after_name.split_whitespace().collect();
    let user = fields
        .get(11)
        .ok_or_else(|| other_error("missing process utime"))?
        .parse::<u64>()?;
    let system = fields
        .get(12)
        .ok_or_else(|| other_error("missing process stime"))?
        .parse::<u64>()?;
    Ok(user.saturating_add(system))
}

fn read_peak_rss_kib(pid: u32) -> LabResult<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmHWM:") {
            return Ok(value
                .split_whitespace()
                .next()
                .ok_or_else(|| other_error("VmHWM value missing"))?
                .parse()?);
        }
    }
    Err(other_error("VmHWM missing"))
}

fn other_error(message: impl Into<String>) -> LabError {
    io::Error::other(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_dev_parser_reads_named_interface() {
        let sample = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n fwbr1: 2456 2 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n";
        let stats = parse_interface_stats_from(sample, "fwbr1").unwrap();
        assert_eq!(stats.rx_bytes, 2_456);
        assert_eq!(stats.rx_packets, 2);
    }

    #[test]
    fn phase_gate_distinguishes_application_and_line_limits() {
        let application = synthetic_observation(Phase::ApplicationLimited, 4.0, 12.5, 0.0);
        assert!(phase_gate(&application));
        let line = synthetic_observation(Phase::LineLimited, 8.0, 25.0, 0.0);
        assert!(phase_gate(&line));
        let wrong = synthetic_observation(Phase::LineLimited, 8.0, 12.5, 0.0);
        assert!(!phase_gate(&wrong));
    }

    #[test]
    fn cross_traffic_gate_requires_total_ingress_and_per_flow_separation() {
        let cross = synthetic_observation(Phase::CrossTraffic, 0.0, 7.0, 18.0);
        assert!(phase_gate(&cross));
        let hidden = synthetic_observation(Phase::CrossTraffic, 0.0, 25.0, 0.0);
        assert!(!phase_gate(&hidden));
    }

    fn synthetic_observation(
        phase: Phase,
        line_one_received_mbps: f64,
        line_two_primary_received_mbps: f64,
        line_two_cross_received_mbps: f64,
    ) -> PhaseObservation {
        let elapsed = Duration::from_secs(2);
        let packets = |mbps: f64| {
            (mbps * elapsed.as_secs_f64() * 1_000_000.0 / (ESTIMATED_WIRE_BYTES as f64 * 8.0))
                .round() as u64
        };
        let specs = phase.flow_specs();
        let mut target_mbps = [0.0; FLOW_COUNT];
        let mut offered_packets = [0_u64; FLOW_COUNT];
        for spec in specs {
            target_mbps[spec.flow.index()] = spec.target_mbps;
            offered_packets[spec.flow.index()] = packets(spec.target_mbps);
        }
        let received_packets = [
            packets(line_one_received_mbps),
            packets(line_two_primary_received_mbps),
            packets(line_two_cross_received_mbps),
        ];
        let line_one_bytes = received_packets[0] * ESTIMATED_WIRE_BYTES as u64;
        let line_two_bytes =
            (received_packets[1] + received_packets[2]) * ESTIMATED_WIRE_BYTES as u64;
        PhaseObservation {
            phase,
            elapsed,
            target_mbps,
            offered_packets,
            sender_errors: 0,
            receiver: ReceiverPhaseReport {
                phase,
                elapsed,
                line_one: InterfaceStats {
                    rx_bytes: line_one_bytes,
                    rx_packets: received_packets[0],
                },
                line_two: InterfaceStats {
                    rx_bytes: line_two_bytes,
                    rx_packets: received_packets[1] + received_packets[2],
                },
                counters: ReceiverCounterSnapshot {
                    packets: received_packets,
                    payload_bytes: received_packets.map(|packets| packets * PAYLOAD_BYTES as u64),
                    ..ReceiverCounterSnapshot::default()
                },
            },
            namespace_separated: true,
            accounting_pass: true,
            phase_pass: false,
        }
    }

    fn parse_interface_stats_from(contents: &str, interface: &str) -> LabResult<InterfaceStats> {
        for line in contents.lines() {
            let Some((name, fields)) = line.split_once(':') else {
                continue;
            };
            if name.trim() != interface {
                continue;
            }
            let mut fields = fields.split_whitespace();
            return Ok(InterfaceStats {
                rx_bytes: fields.next().unwrap().parse()?,
                rx_packets: fields.next().unwrap().parse()?,
            });
        }
        Err(other_error("interface missing"))
    }
}
