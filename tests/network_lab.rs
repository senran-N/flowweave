use std::{env, fmt::Write as _, fs, io, process::Command, time::Duration};

use flowweave_lab::{
    ContinuousBenchmarkConfig, ContinuousBenchmarkReport, DatagramMeasurement,
    DeclaredBackloggedEpochConfig, DeclaredBackloggedEpochReport, FailoverDirection,
    FailoverReport, HysteriaCongestion, HysteriaFailoverConfig, HysteriaFailoverReport,
    HysteriaLine, HysteriaRealtimeConfig, HysteriaRealtimeReport, HysteriaThroughputConfig,
    HysteriaThroughputReport, LabResult, MultipathScheduler, NetworkBenchmarkConfig,
    NetworkBenchmarkReport, PathMode, PtoRecovery, QuicCongestion, RealtimeControllerGateConfig,
    RealtimeControllerGateReport, RealtimeDatagramConfig, RealtimeDatagramReport,
    RealtimeV3WireConfig, RealtimeV3WireReport, RealtimeV4Config, RealtimeV4Report,
    RealtimeV12Config, RealtimeV12Report, SustainedBenchmarkConfig, SustainedFailoverConfig,
    SustainedFailoverReport, run_batched_duplication_realtime, run_blackhole_failover,
    run_continuous_network_benchmark, run_declared_backlogged_epoch_probe, run_hysteria_failover,
    run_hysteria_realtime, run_hysteria_throughput, run_network_benchmark,
    run_realtime_controller_gate, run_sustained_blackhole_failover,
    run_sustained_network_benchmark, run_v3_wire_latency_probe, run_v4_bbr3_coding_realtime,
    run_v12_bbr3_two_of_three_realtime, verify_hysteria_binary,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const SCREENING_TRANSFER_SIZE: usize = 2 * MIB;
const LONG_WARMUP_DURATION: Duration = Duration::from_secs(2);
const LONG_MEASUREMENT_DURATION: Duration = Duration::from_secs(20);
const LONG_CHUNK_SIZE: usize = 512 * KIB;
const FORMAL_FAILOVER_DURATION: Duration = Duration::from_secs(30);
const FORMAL_FAILOVER_AT: Duration = Duration::from_secs(10);
const FORMAL_FAILOVER_CHUNK_SIZE: usize = 16 * KIB;
const FORMAL_FAILOVER_CANDIDATE: PtoRecovery = PtoRecovery::CrossPathRecoveryWithFeedbackHandoff;
const FORMAL_FAILOVER_PARTICIPANTS: [PtoRecovery; 2] =
    [PtoRecovery::Disabled, FORMAL_FAILOVER_CANDIDATE];
const C_SMOKE_DURATION: Duration = Duration::from_secs(10);
const C_FORMAL_DURATION: Duration = Duration::from_secs(60);
const B_CONTROLLER_GATE_WARMUP: Duration = Duration::from_secs(2);
const B_CONTROLLER_GATE_MEASUREMENT: Duration = Duration::from_secs(5);
const B_CONTROLLER_GATE_CHUNK_SIZE: usize = 16 * KIB;
const B_DECLARED_EPOCH_WARMUP: Duration = Duration::from_secs(2);
const B_DECLARED_EPOCH_MEASUREMENT: Duration = Duration::from_secs(5);
const B_DECLARED_EPOCH_CHUNK_SIZE: usize = 16 * KIB;
const B_DECLARED_EPOCH_COHORTS: u64 = 20;
const B_CONTINUOUS_FORMAL_WARMUP: Duration = Duration::from_secs(2);
const B_CONTINUOUS_FORMAL_MEASUREMENT: Duration = Duration::from_secs(20);
const B_CONTINUOUS_FORMAL_CHUNK_SIZE: usize = 16 * KIB;
const B_CONTINUOUS_FORMAL_WIRE_RATIO_LIMIT: f64 = 1.10;
const B_CONTINUOUS_FORMAL_GAIN_RATIO: f64 = 1.15;
const B_CONTINUOUS_FORMAL_MINIMUM_SHARE_PERCENT: f64 = 10.0;
const HYSTERIA_B_WARMUP: Duration = Duration::from_secs(2);
const HYSTERIA_B_SMOKE_MEASUREMENT: Duration = Duration::from_secs(5);
const HYSTERIA_B_FORMAL_MEASUREMENT: Duration = Duration::from_secs(20);
const HYSTERIA_B_CHUNK_SIZE: usize = 16 * KIB;
const FLOWWEAVE_B_BALANCED_THROUGHPUT_MEDIAN: f64 = 26.579_653;
const FLOWWEAVE_B_HETEROGENEOUS_THROUGHPUT_MEDIAN: f64 = 27.509_019;
const FLOWWEAVE_B_BALANCED_WIRE_RATIO_MEDIAN: f64 = 1.021_995;
const FLOWWEAVE_B_HETEROGENEOUS_WIRE_RATIO_MEDIAN: f64 = 1.025_370;

#[derive(Clone, Copy)]
struct LinkProfile {
    delay: &'static str,
    loss: &'static str,
    rate: &'static str,
}

impl LinkProfile {
    const fn new(delay: &'static str, loss: &'static str, rate: &'static str) -> Self {
        Self { delay, loss, rate }
    }
}

#[derive(Clone, Copy)]
struct NetemSeeds {
    line_one: u32,
    line_two: u32,
}

const SEED_PAIRS: [NetemSeeds; 5] = [
    NetemSeeds {
        line_one: 1101,
        line_two: 2201,
    },
    NetemSeeds {
        line_one: 1102,
        line_two: 2202,
    },
    NetemSeeds {
        line_one: 1103,
        line_two: 2203,
    },
    NetemSeeds {
        line_one: 1104,
        line_two: 2204,
    },
    NetemSeeds {
        line_one: 1105,
        line_two: 2205,
    },
];

const FORMAL_APPLICATION_PROGRESS_FAILURE_CASES: [(FailoverDirection, usize, usize, u8); 4] = [
    (FailoverDirection::ClientToServer, 6, 0, 183),
    (FailoverDirection::ClientToServer, 9, 3, 186),
    (FailoverDirection::ServerToClient, 8, 2, 202),
    (FailoverDirection::ServerToClient, 10, 4, 204),
];
const REVERSE_ROUND_8_CASE: (FailoverDirection, usize, usize, u8) =
    (FailoverDirection::ServerToClient, 8, 2, 202);
const FORWARD_FORMAL_ROUND_10_CASE: (FailoverDirection, usize, usize, u8) =
    (FailoverDirection::ClientToServer, 10, 4, 187);

#[derive(Clone, Copy, PartialEq, Eq)]
enum AggregationScenario {
    Balanced,
    Heterogeneous,
}

impl AggregationScenario {
    const ALL: [Self; 2] = [Self::Balanced, Self::Heterogeneous];

    fn description(self) -> &'static str {
        match self {
            Self::Balanced => "平衡 15+15 Mbit/s",
            Self::Heterogeneous => "异构 8+25 Mbit/s",
        }
    }

    fn profiles(self) -> (LinkProfile, LinkProfile) {
        match self {
            Self::Balanced => (
                LinkProfile::new("20ms", "0.1%", "15mbit"),
                LinkProfile::new("20ms", "0.1%", "15mbit"),
            ),
            Self::Heterogeneous => (
                LinkProfile::new("15ms", "0.1%", "8mbit"),
                LinkProfile::new("50ms", "0.1%", "25mbit"),
            ),
        }
    }

    const fn hysteria_bandwidth_mbps(self, line: HysteriaLine) -> u32 {
        match (self, line) {
            (Self::Balanced, _) => 15,
            (Self::Heterogeneous, HysteriaLine::One) => 8,
            (Self::Heterogeneous, HysteriaLine::Two) => 25,
        }
    }

    const fn flowweave_throughput_median(self) -> f64 {
        match self {
            Self::Balanced => FLOWWEAVE_B_BALANCED_THROUGHPUT_MEDIAN,
            Self::Heterogeneous => FLOWWEAVE_B_HETEROGENEOUS_THROUGHPUT_MEDIAN,
        }
    }

    const fn flowweave_wire_ratio_median(self) -> f64 {
        match self {
            Self::Balanced => FLOWWEAVE_B_BALANCED_WIRE_RATIO_MEDIAN,
            Self::Heterogeneous => FLOWWEAVE_B_HETEROGENEOUS_WIRE_RATIO_MEDIAN,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScreeningParticipant {
    LineOne,
    LineTwo,
    Multipath(MultipathScheduler),
}

impl ScreeningParticipant {
    const ALL: [Self; 3] = [
        Self::LineOne,
        Self::LineTwo,
        Self::Multipath(MultipathScheduler::NoqDefault),
    ];

    fn description(self) -> &'static str {
        match self {
            Self::LineOne => "仅线路一",
            Self::LineTwo => "仅线路二",
            Self::Multipath(scheduler) => scheduler.description(),
        }
    }

    fn config(self) -> NetworkBenchmarkConfig {
        match self {
            Self::LineOne => NetworkBenchmarkConfig::new(
                PathMode::LineOneOnly,
                MultipathScheduler::NoqDefault,
                SCREENING_TRANSFER_SIZE,
                0,
            ),
            Self::LineTwo => NetworkBenchmarkConfig::new(
                PathMode::LineTwoOnly,
                MultipathScheduler::NoqDefault,
                SCREENING_TRANSFER_SIZE,
                0,
            ),
            Self::Multipath(scheduler) => NetworkBenchmarkConfig::new(
                PathMode::MultipathAvailable,
                scheduler,
                SCREENING_TRANSFER_SIZE,
                0,
            ),
        }
    }

    fn sustained_config(self) -> SustainedBenchmarkConfig {
        let (mode, scheduler) = match self {
            Self::LineOne => (PathMode::LineOneOnly, MultipathScheduler::NoqDefault),
            Self::LineTwo => (PathMode::LineTwoOnly, MultipathScheduler::NoqDefault),
            Self::Multipath(scheduler) => (PathMode::MultipathAvailable, scheduler),
        };
        SustainedBenchmarkConfig::new(
            mode,
            scheduler,
            LONG_WARMUP_DURATION,
            LONG_MEASUREMENT_DURATION,
            LONG_CHUNK_SIZE,
        )
    }
}

struct ScreeningObservation {
    scenario: AggregationScenario,
    round: usize,
    seeds: NetemSeeds,
    participant: ScreeningParticipant,
    report: NetworkBenchmarkReport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BControllerParticipant {
    CubicLineOne,
    CubicLineTwo,
    CubicMultipath,
    Bbr3LineOne,
    Bbr3LineTwo,
    Bbr3Multipath,
}

impl BControllerParticipant {
    const ALL: [Self; 6] = [
        Self::CubicLineOne,
        Self::CubicLineTwo,
        Self::CubicMultipath,
        Self::Bbr3LineOne,
        Self::Bbr3LineTwo,
        Self::Bbr3Multipath,
    ];

    const fn description(self) -> &'static str {
        match self {
            Self::CubicLineOne => "Cubic / 仅线路一",
            Self::CubicLineTwo => "Cubic / 仅线路二",
            Self::CubicMultipath => "Cubic / NoQ 默认双路",
            Self::Bbr3LineOne => "BBR3 / 仅线路一",
            Self::Bbr3LineTwo => "BBR3 / 仅线路二",
            Self::Bbr3Multipath => "BBR3 / NoQ 默认双路",
        }
    }

    const fn congestion(self) -> QuicCongestion {
        match self {
            Self::CubicLineOne | Self::CubicLineTwo | Self::CubicMultipath => QuicCongestion::Cubic,
            Self::Bbr3LineOne | Self::Bbr3LineTwo | Self::Bbr3Multipath => QuicCongestion::Bbr3,
        }
    }

    const fn mode(self) -> PathMode {
        match self {
            Self::CubicLineOne | Self::Bbr3LineOne => PathMode::LineOneOnly,
            Self::CubicLineTwo | Self::Bbr3LineTwo => PathMode::LineTwoOnly,
            Self::CubicMultipath | Self::Bbr3Multipath => PathMode::MultipathAvailable,
        }
    }

    fn config(self) -> SustainedBenchmarkConfig {
        SustainedBenchmarkConfig::new(
            self.mode(),
            MultipathScheduler::NoqDefault,
            B_CONTROLLER_GATE_WARMUP,
            B_CONTROLLER_GATE_MEASUREMENT,
            B_CONTROLLER_GATE_CHUNK_SIZE,
        )
        .with_congestion(self.congestion())
    }
}

struct BControllerObservation {
    scenario: AggregationScenario,
    seeds: NetemSeeds,
    participant: BControllerParticipant,
    report: NetworkBenchmarkReport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BDeclaredEpochParticipant {
    LineOne,
    LineTwo,
}

impl BDeclaredEpochParticipant {
    const ALL: [Self; 2] = [Self::LineOne, Self::LineTwo];

    const fn description(self) -> &'static str {
        match self {
            Self::LineOne => "Cubic / 仅线路一",
            Self::LineTwo => "Cubic / 仅线路二",
        }
    }

    const fn mode(self) -> PathMode {
        match self {
            Self::LineOne => PathMode::LineOneOnly,
            Self::LineTwo => PathMode::LineTwoOnly,
        }
    }

    fn config(self) -> DeclaredBackloggedEpochConfig {
        DeclaredBackloggedEpochConfig::new(
            self.mode(),
            B_DECLARED_EPOCH_WARMUP,
            B_DECLARED_EPOCH_MEASUREMENT,
            B_DECLARED_EPOCH_CHUNK_SIZE,
        )
    }
}

struct BDeclaredEpochObservation {
    scenario: AggregationScenario,
    seeds: NetemSeeds,
    participant: BDeclaredEpochParticipant,
    report: DeclaredBackloggedEpochReport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BContinuousParticipant {
    LineOne,
    LineTwo,
    Multipath,
}

impl BContinuousParticipant {
    const ALL: [Self; 3] = [Self::LineOne, Self::LineTwo, Self::Multipath];

    const fn description(self) -> &'static str {
        match self {
            Self::LineOne => "Cubic / 仅线路一",
            Self::LineTwo => "Cubic / 仅线路二",
            Self::Multipath => "Cubic / NoQ 默认双路",
        }
    }

    const fn mode(self) -> PathMode {
        match self {
            Self::LineOne => PathMode::LineOneOnly,
            Self::LineTwo => PathMode::LineTwoOnly,
            Self::Multipath => PathMode::MultipathAvailable,
        }
    }

    fn config(self) -> ContinuousBenchmarkConfig {
        ContinuousBenchmarkConfig::new(
            self.mode(),
            MultipathScheduler::NoqDefault,
            B_CONTINUOUS_FORMAL_WARMUP,
            B_CONTINUOUS_FORMAL_MEASUREMENT,
            B_CONTINUOUS_FORMAL_CHUNK_SIZE,
        )
    }
}

struct BContinuousObservation {
    scenario: AggregationScenario,
    round: usize,
    seeds: NetemSeeds,
    participant: BContinuousParticipant,
    report: ContinuousBenchmarkReport,
}

struct RecoveryScreeningObservation {
    round: usize,
    seeds: NetemSeeds,
    pto_recovery: PtoRecovery,
    failover: FailoverReport,
    normal: NetworkBenchmarkReport,
    high_loss: NetworkBenchmarkReport,
}

struct FormalFailoverObservation {
    direction: FailoverDirection,
    round: usize,
    seeds: NetemSeeds,
    pto_recovery: PtoRecovery,
    report: SustainedFailoverReport,
}

struct RealtimeObservation {
    round: usize,
    seeds: NetemSeeds,
    report: RealtimeDatagramReport,
}

struct RealtimeV3WireObservation {
    round: usize,
    seeds: NetemSeeds,
    report: RealtimeV3WireReport,
}

struct RealtimeControllerGateObservation {
    round: usize,
    seeds: NetemSeeds,
    report: RealtimeControllerGateReport,
}

struct RealtimeV4Observation {
    round: usize,
    seeds: NetemSeeds,
    report: RealtimeV4Report,
}

struct RealtimeV12Observation {
    round: usize,
    seeds: NetemSeeds,
    report: RealtimeV12Report,
}

struct HysteriaRealtimeObservation {
    round: usize,
    seeds: NetemSeeds,
    report: HysteriaRealtimeReport,
}

struct HysteriaFailoverObservation {
    direction: FailoverDirection,
    round: usize,
    seeds: NetemSeeds,
    report: HysteriaFailoverReport,
}

struct HysteriaThroughputObservation {
    scenario: AggregationScenario,
    round: usize,
    seeds: NetemSeeds,
    payload_seed: u8,
    report: HysteriaThroughputReport,
}

struct NumericSummary {
    median: f64,
    p95: f64,
    worst: f64,
    minimum: f64,
    maximum: f64,
}

impl NumericSummary {
    fn from_samples(samples: impl IntoIterator<Item = f64>) -> Self {
        let mut samples: Vec<_> = samples.into_iter().collect();
        assert!(!samples.is_empty(), "summary requires samples");
        samples.sort_by(f64::total_cmp);
        let median = samples[samples.len() / 2];
        let p95_index = ((samples.len() * 95).div_ceil(100)).saturating_sub(1);
        let minimum = samples[0];
        let maximum = samples[samples.len() - 1];
        Self {
            median,
            p95: samples[p95_index],
            worst: minimum,
            minimum,
            maximum,
        }
    }

    fn range(&self) -> f64 {
        self.maximum - self.minimum
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh 在隔离网络命名空间中运行"]
async fn controlled_bad_network_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    println!();
    println!("FlowWeave / 织流 第二阶段 A：可重复坏网络实验");
    println!("所有网络限制只存在于本次一次性网络命名空间，不会修改真实网卡。");

    println!();
    println!("场景一：两条质量不同、但都可用的线路");
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");
    let normal_multipath =
        benchmark_recovery_candidates(normal_line_one, normal_line_two, 512 * KIB, 48).await?;
    for report in &normal_multipath {
        print_benchmark(report);
    }

    println!();
    println!("场景二：传输中主线路突然变为 100% 丢包");
    for pto_recovery in PtoRecovery::CANDIDATES {
        apply_profiles(normal_line_one, normal_line_two, SEED_PAIRS[0])?;
        let failover = run_blackhole_failover(
            MultipathScheduler::NoqDefault,
            pto_recovery,
            || {
                replace_line_profile(
                    "1:1",
                    "10:",
                    LinkProfile::new("20ms", "100%", "20mbit"),
                    SEED_PAIRS[0].line_one,
                )
            },
            || replace_line_profile("1:1", "10:", normal_line_one, SEED_PAIRS[0].line_one),
        )
        .await?;
        print_failover(&failover);
    }

    println!();
    println!("场景三：线路一丢包 8%，线路二丢包 2%");
    let high_loss_line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let high_loss_line_two = LinkProfile::new("40ms", "2%", "20mbit");
    apply_profiles(high_loss_line_one, high_loss_line_two, SEED_PAIRS[0])?;
    let loss_line_one = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::LineOneOnly,
        MultipathScheduler::NoqDefault,
        384 * KIB,
        72,
    ))
    .await?;
    apply_profiles(high_loss_line_one, high_loss_line_two, SEED_PAIRS[0])?;
    let loss_line_two = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::LineTwoOnly,
        MultipathScheduler::NoqDefault,
        384 * KIB,
        72,
    ))
    .await?;
    let loss_multipath =
        benchmark_recovery_candidates(high_loss_line_one, high_loss_line_two, 384 * KIB, 72)
            .await?;
    print_benchmark(&loss_line_one);
    print_benchmark(&loss_line_two);
    for report in &loss_multipath {
        print_benchmark(report);
        print_comparison("高丢包吞吐量", &loss_line_one, &loss_line_two, report);
    }

    println!();
    println!("场景四：8 Mbit/s 低延迟线路 + 25 Mbit/s 高延迟线路");
    let slow_low_latency = LinkProfile::new("15ms", "0%", "8mbit");
    let fast_high_latency = LinkProfile::new("50ms", "0%", "25mbit");
    apply_profiles(slow_low_latency, fast_high_latency, SEED_PAIRS[0])?;
    let speed_line_one = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::LineOneOnly,
        MultipathScheduler::NoqDefault,
        MIB,
        0,
    ))
    .await?;
    apply_profiles(slow_low_latency, fast_high_latency, SEED_PAIRS[0])?;
    let speed_line_two = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::LineTwoOnly,
        MultipathScheduler::NoqDefault,
        MIB,
        0,
    ))
    .await?;
    let speed_multipath =
        benchmark_multipath_candidates(slow_low_latency, fast_high_latency, MIB, 0).await?;
    print_benchmark(&speed_line_one);
    print_benchmark(&speed_line_two);
    for report in &speed_multipath {
        print_benchmark(report);
        print_comparison("异构线路吞吐量", &speed_line_one, &speed_line_two, report);
    }

    println!();
    println!("实验结论是当前调度矩阵的单轮基础测量，不是五种子最终结论，也不代表已经实现 FEC。");
    print_tc_statistics()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v2-smoke 在隔离网络命名空间中运行"]
async fn c_batched_duplication_v2_five_message_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-c-batched-duplication-v2-five-message-smoke.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    run_c_batched_duplication_matrix(RESULT_PATH, C_SMOKE_DURATION, &SEED_PAIRS[..1], true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v2-formal 在隔离网络命名空间中运行"]
async fn c_batched_duplication_v2_five_message_formal_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-c-batched-duplication-v2-five-message-formal-5.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    run_c_batched_duplication_matrix(RESULT_PATH, C_FORMAL_DURATION, &SEED_PAIRS, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v3-wire 在隔离网络命名空间中运行"]
async fn c_pair_xor_global_10_2_v3_wire_latency_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-c-pair-xor-global-10-2-v3-wire-latency-smoke.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    ensure_isolated_network_namespace()?;
    let seeds = SEED_PAIRS[0];
    let line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let line_two = LinkProfile::new("40ms", "2%", "20mbit");
    let mut observations = Vec::with_capacity(1);
    write_realtime_v3_wire_csv(RESULT_PATH, &observations)?;

    println!();
    println!("FlowWeave / 织流：C 组 v3 精确线速与基础延迟门控");
    println!(
        "固定生成 100 条/秒、每条 200 字节，持续 {:.0} 秒；每 10 条发送 10 个主路原件、5 个主路成对 XOR、2 个备用路全局校验。",
        C_SMOKE_DURATION.as_secs_f64()
    );
    println!("线路一 20 ms / 8%，线路二 40 ms / 2%，所有数据与校验逐帧确认独立构包。");

    apply_profiles(line_one, line_two, seeds)?;
    let report = run_v3_wire_latency_probe(RealtimeV3WireConfig::new(C_SMOKE_DURATION)).await?;
    print_realtime_v3_wire_report(&report);
    observations.push(RealtimeV3WireObservation {
        round: 1,
        seeds,
        report,
    });
    write_realtime_v3_wire_csv(RESULT_PATH, &observations)?;
    print_tc_statistics()?;

    if !observations[0].report.wire_latency_gate_pass() {
        return Err(lab_error(format!(
            "C 组 v3 线速/基础延迟门控未通过；原始数据已保留在 {RESULT_PATH}，不得继续完整解码烟测"
        )));
    }
    println!();
    println!("C 组 v3 线速/基础延迟门控通过，原始数据已写入 {RESULT_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-controller-gate 在隔离网络命名空间中运行"]
async fn c_small_datagram_controller_gate_v1_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-c-small-datagram-controller-gate-v1-smoke.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    ensure_isolated_network_namespace()?;
    let seeds = SEED_PAIRS[0];
    let line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let line_two = LinkProfile::new("40ms", "2%", "20mbit");
    let mut observations = Vec::with_capacity(QuicCongestion::ALL.len());
    write_realtime_controller_gate_csv(RESULT_PATH, &observations)?;

    println!();
    println!("FlowWeave / 织流：C 组小 DATAGRAM 拥塞控制/发送节奏隔离门控");
    println!(
        "Cubic 与 BBR3 各发送 1000 条立即主路原件；无副本、无编码、无逐帧构包轮询，P95 必须严格低于 23.726 ms。"
    );

    for (index, congestion) in QuicCongestion::ALL.into_iter().enumerate() {
        println!();
        println!("参赛项：{}", congestion.description());
        apply_profiles(line_one, line_two, seeds)?;
        let report = run_realtime_controller_gate(RealtimeControllerGateConfig::new(
            C_SMOKE_DURATION,
            congestion,
        ))
        .await?;
        print_realtime_controller_gate_report(&report);
        observations.push(RealtimeControllerGateObservation {
            round: index + 1,
            seeds,
            report,
        });
        write_realtime_controller_gate_csv(RESULT_PATH, &observations)?;
    }
    print_tc_statistics()?;

    if !observations
        .iter()
        .any(|observation| observation.report.feasibility_gate_pass())
    {
        return Err(lab_error(format!(
            "C 组 Cubic/BBR3 小 DATAGRAM 基础 P95 均未通过；原始数据已保留在 {RESULT_PATH}"
        )));
    }
    println!();
    println!("至少一个 C 组基础控制器门控通过，原始数据已写入 {RESULT_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v4-smoke 在隔离网络命名空间中运行"]
async fn c_bbr3_pair_xor_global_10_2_v4_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-c-bbr3-pair-xor-global-10-2-v4-smoke.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    run_c_v4_matrix(RESULT_PATH, C_SMOKE_DURATION, &SEED_PAIRS[..1], false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v4-formal 在隔离网络命名空间中运行"]
async fn c_bbr3_pair_xor_global_10_2_v4_formal_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-c-bbr3-pair-xor-global-10-2-v4-formal-5.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    run_c_v4_matrix(RESULT_PATH, C_FORMAL_DURATION, &SEED_PAIRS, true).await
}

async fn run_c_v4_matrix(
    result_path: &str,
    duration: Duration,
    seeds: &[NetemSeeds],
    enforce_total_loss: bool,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    let line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let line_two = LinkProfile::new("40ms", "2%", "20mbit");
    let mut observations = Vec::with_capacity(seeds.len());
    write_realtime_v4_csv(result_path, &observations)?;

    println!();
    println!("FlowWeave / 织流：C 组 BBR3 + 成对 XOR + 双全局校验 v4");
    println!(
        "固定生成 100 条/秒、每条 200 字节，持续 {:.0} 秒；每 10 条发送 10 个主路原件、5 个主路成对 XOR、2 个备用路全局校验。",
        duration.as_secs_f64()
    );
    println!("所有应用 DATAGRAM 使用协议内独立包边界；P95 必须严格低于 23.726 ms。");

    for (round_index, seeds) in seeds.iter().copied().enumerate() {
        let round = round_index + 1;
        println!();
        println!(
            "第 {round} 轮：线路一种子 {}，线路二种子 {}",
            seeds.line_one, seeds.line_two
        );
        apply_profiles(line_one, line_two, seeds)?;
        let report = run_v4_bbr3_coding_realtime(RealtimeV4Config::new(duration)).await?;
        print_realtime_v4_report(&report);
        observations.push(RealtimeV4Observation {
            round,
            seeds,
            report,
        });
        write_realtime_v4_csv(result_path, &observations)?;
    }
    print_tc_statistics()?;

    let failed_rounds = observations
        .iter()
        .filter(|observation| !observation.report.stage_pass())
        .map(|observation| observation.round.to_string())
        .collect::<Vec<_>>();
    let total_lost = observations
        .iter()
        .map(|observation| observation.report.lost_messages)
        .sum::<usize>();
    if !failed_rounds.is_empty() || (enforce_total_loss && total_lost > 283) {
        return Err(lab_error(format!(
            "C 组 v4 未通过预注册门槛；失败轮次：{}；五轮总丢失 {}；原始数据已保留在 {result_path}",
            if failed_rounds.is_empty() {
                "无".to_owned()
            } else {
                failed_rounds.join("、")
            },
            total_lost
        )));
    }

    println!();
    println!(
        "C 组 v4 {}通过，累计丢失 {}，原始数据已写入 {result_path}",
        if enforce_total_loss {
            "正式五种子矩阵"
        } else {
            "烟测"
        },
        total_lost
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v12-smoke 在隔离网络命名空间中运行"]
async fn c_bbr3_no_gso_compact7_two_of_three_global_40_3_v12_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-c-bbr3-no-gso-compact7-two-of-three-global-40-3-v12-smoke.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    run_c_v12_matrix(RESULT_PATH, C_SMOKE_DURATION, &SEED_PAIRS[..1], false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh c-v12-formal 在隔离网络命名空间中运行"]
async fn c_bbr3_no_gso_compact7_two_of_three_global_40_3_v12_formal_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-c-bbr3-no-gso-compact7-two-of-three-global-40-3-v12-formal-5.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    run_c_v12_matrix(RESULT_PATH, C_FORMAL_DURATION, &SEED_PAIRS, true).await
}

async fn run_c_v12_matrix(
    result_path: &str,
    duration: Duration,
    seeds: &[NetemSeeds],
    enforce_total_loss: bool,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    let line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let line_two = LinkProfile::new("40ms", "2%", "20mbit");
    let mut observations = Vec::with_capacity(seeds.len());
    write_realtime_v12_csv(result_path, &observations)?;

    println!();
    println!("FlowWeave / 织流：C 组 BBR3 + no-GSO 每消息 2-of-3 小分片 + 40/3 全局校验 v12");
    println!(
        "固定生成 100 条/秒、每条 200 字节，持续 {:.0} 秒；每条在主路发送 Data0/Data1/LocalParity 三个 100 字节分片，每 20 条在备用路发送 3 个全局校验分片。",
        duration.as_secs_f64()
    );
    println!(
        "使用 7 字节紧凑头/107 字节固定帧，所有应用 DATAGRAM 独立构包且 transport 禁用 segmentation offload；P95 必须严格低于 23.726 ms。"
    );

    for (round_index, seeds) in seeds.iter().copied().enumerate() {
        let round = round_index + 1;
        println!();
        println!(
            "第 {round} 轮：线路一种子 {}，线路二种子 {}",
            seeds.line_one, seeds.line_two
        );
        apply_profiles(line_one, line_two, seeds)?;
        let report = run_v12_bbr3_two_of_three_realtime(RealtimeV12Config::new(duration)).await?;
        print_realtime_v12_report(&report);
        observations.push(RealtimeV12Observation {
            round,
            seeds,
            report,
        });
        write_realtime_v12_csv(result_path, &observations)?;
    }
    print_tc_statistics()?;

    let failed_rounds = observations
        .iter()
        .filter(|observation| !observation.report.stage_pass())
        .map(|observation| observation.round.to_string())
        .collect::<Vec<_>>();
    let total_lost = observations
        .iter()
        .map(|observation| observation.report.lost_messages)
        .sum::<usize>();
    if !failed_rounds.is_empty() || (enforce_total_loss && total_lost > 283) {
        return Err(lab_error(format!(
            "C 组 v12 未通过预注册门槛；失败轮次：{}；五轮总丢失 {}；原始数据已保留在 {result_path}",
            if failed_rounds.is_empty() {
                "无".to_owned()
            } else {
                failed_rounds.join("、")
            },
            total_lost
        )));
    }

    println!();
    println!(
        "C 组 v12 {}通过，累计丢失 {}，原始数据已写入 {result_path}",
        if enforce_total_loss {
            "正式五种子矩阵"
        } else {
            "烟测"
        },
        total_lost
    );
    Ok(())
}

async fn run_c_batched_duplication_matrix(
    result_path: &str,
    duration: Duration,
    seeds: &[NetemSeeds],
    smoke_only: bool,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    let line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let line_two = LinkProfile::new("40ms", "2%", "20mbit");
    let mut observations = Vec::with_capacity(seeds.len());
    write_realtime_csv(result_path, &observations)?;

    println!();
    println!("FlowWeave / 织流：C 组五消息批量双路径副本 v2");
    println!(
        "固定生成 100 条/秒、每条 200 字节，持续 {:.0} 秒；两条路径各发送一个相同五消息批次。",
        duration.as_secs_f64()
    );
    println!("线路一 20 ms / 8%，线路二 40 ms / 2%，带宽均为 20 Mbit/s。");

    for (round_index, seeds) in seeds.iter().copied().enumerate() {
        let round = round_index + 1;
        println!();
        println!(
            "第 {round} 轮：线路一种子 {}，线路二种子 {}",
            seeds.line_one, seeds.line_two
        );
        apply_profiles(line_one, line_two, seeds)?;
        let report =
            run_batched_duplication_realtime(RealtimeDatagramConfig::new(duration)).await?;
        print_realtime_report(&report);
        observations.push(RealtimeObservation {
            round,
            seeds,
            report,
        });
        write_realtime_csv(result_path, &observations)?;
    }

    print_tc_statistics()?;
    let failed = observations.iter().filter(|observation| {
        if smoke_only {
            !observation.report.smoke_safety_pass()
        } else {
            !observation.report.stage_pass()
        }
    });
    let failed_rounds = failed
        .map(|observation| observation.round.to_string())
        .collect::<Vec<_>>();
    if !failed_rounds.is_empty() {
        return Err(lab_error(format!(
            "C 组 v2 {}未通过预注册门槛，失败轮次：{}；原始数据已保留在 {result_path}",
            if smoke_only { "烟测" } else { "正式矩阵" },
            failed_rounds.join("、")
        )));
    }

    println!();
    println!(
        "C 组 v2 {}通过，原始数据已写入 {result_path}",
        if smoke_only {
            "烟测"
        } else {
            "正式五种子矩阵"
        }
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-c-wire 在隔离网络命名空间中运行"]
async fn hysteria_c_wiring_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    let binary = hysteria_binary_path()?;
    verify_hysteria_binary(&binary)?;
    apply_profiles(
        LinkProfile::new("20ms", "8%", "20mbit"),
        LinkProfile::new("40ms", "2%", "20mbit"),
        SEED_PAIRS[0],
    )?;
    let report = run_hysteria_realtime(HysteriaRealtimeConfig::new(
        binary,
        HysteriaCongestion::Bbr,
        HysteriaLine::One,
        Duration::from_secs(1),
    ))
    .await?;
    print_hysteria_realtime_report(&report);
    if !report.smoke_safety_pass() {
        return Err(lab_error("Hysteria C 组一秒接线诊断没有闭合"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-c-smoke 在隔离网络命名空间中运行"]
async fn hysteria_c_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-hysteria-2-9-3-c-smoke-v2.csv";
    run_hysteria_c_matrix(RESULT_PATH, C_SMOKE_DURATION, &SEED_PAIRS[..1]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-c-formal 在隔离网络命名空间中运行"]
async fn hysteria_c_formal_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-hysteria-2-9-3-c-formal-20-v2.csv";
    run_hysteria_c_matrix(RESULT_PATH, C_FORMAL_DURATION, &SEED_PAIRS).await
}

async fn run_hysteria_c_matrix(
    result_path: &str,
    duration: Duration,
    seeds: &[NetemSeeds],
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    ensure_benchmark_paths_absent(&[result_path])?;
    let binary = hysteria_binary_path()?;
    verify_hysteria_binary(&binary)?;
    let line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let line_two = LinkProfile::new("40ms", "2%", "20mbit");
    let base_participants = [
        (HysteriaCongestion::Bbr, HysteriaLine::One),
        (HysteriaCongestion::Bbr, HysteriaLine::Two),
        (HysteriaCongestion::Brutal, HysteriaLine::One),
        (HysteriaCongestion::Brutal, HysteriaLine::Two),
    ];
    let mut observations = Vec::with_capacity(seeds.len() * base_participants.len());
    write_hysteria_realtime_csv(result_path, &observations)?;

    println!();
    println!("Hysteria 2.9.3：C 组高丢包实时传输公平对照");
    println!(
        "每项固定 100 条/秒、每条 200 字节，持续 {:.0} 秒；BBR/Brutal 分别运行两条单线路。",
        duration.as_secs_f64()
    );

    for (round_index, seeds) in seeds.iter().copied().enumerate() {
        let round = round_index + 1;
        let mut participants = base_participants.to_vec();
        let participant_count = participants.len();
        participants.rotate_left(round_index % participant_count);
        println!();
        println!(
            "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
            seeds.line_one,
            seeds.line_two,
            participants
                .iter()
                .map(|(congestion, line)| format!(
                    "{} / {}",
                    congestion.description(),
                    line.description()
                ))
                .collect::<Vec<_>>()
                .join(" → ")
        );

        for (congestion, line) in participants {
            apply_profiles(line_one, line_two, seeds)?;
            let report = run_hysteria_realtime(HysteriaRealtimeConfig::new(
                binary.clone(),
                congestion,
                line,
                duration,
            ))
            .await?;
            print_hysteria_realtime_report(&report);
            let safety_pass = report.smoke_safety_pass();
            observations.push(HysteriaRealtimeObservation {
                round,
                seeds,
                report,
            });
            write_hysteria_realtime_csv(result_path, &observations)?;
            if !safety_pass {
                return Err(lab_error(format!(
                    "Hysteria C 组基础设施门槛失败：第 {round} 轮 {} / {}；原始数据已保留在 {result_path}",
                    congestion.description(),
                    line.description()
                )));
            }
        }
    }

    print_hysteria_c_summary(&observations);
    print_tc_statistics()?;
    println!();
    println!("Hysteria C 组原始数据已写入 {result_path}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-b-smoke 在隔离网络命名空间中运行"]
async fn hysteria_b_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-hysteria-2-9-3-b-smoke-v2.csv";
    run_hysteria_b_matrix(
        RESULT_PATH,
        HYSTERIA_B_SMOKE_MEASUREMENT,
        &SEED_PAIRS[..1],
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-b-formal 在隔离网络命名空间中运行"]
async fn hysteria_b_formal_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-hysteria-2-9-3-b-formal-40-v2.csv";
    run_hysteria_b_matrix(
        RESULT_PATH,
        HYSTERIA_B_FORMAL_MEASUREMENT,
        &SEED_PAIRS,
        true,
    )
    .await
}

async fn run_hysteria_b_matrix(
    result_path: &str,
    measurement_duration: Duration,
    seeds: &[NetemSeeds],
    enforce_final_comparison: bool,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    ensure_benchmark_paths_absent(&[result_path])?;
    let binary = hysteria_binary_path()?;
    verify_hysteria_binary(&binary)?;
    let base_participants = [
        (HysteriaCongestion::Bbr, HysteriaLine::One),
        (HysteriaCongestion::Bbr, HysteriaLine::Two),
        (HysteriaCongestion::Brutal, HysteriaLine::One),
        (HysteriaCongestion::Brutal, HysteriaLine::Two),
    ];
    let mut observations =
        Vec::with_capacity(AggregationScenario::ALL.len() * seeds.len() * base_participants.len());
    write_hysteria_throughput_csv(result_path, &observations)?;

    println!();
    println!("Hysteria 2.9.3：B 组持续 TCP 吞吐公平对照");
    println!(
        "每项同一 TCP 连接预热 {} 秒，再由接收端连续计时 {:.0} 秒；BBR/Brutal 分别运行两条单线路，Brutal 使用真实线路带宽。",
        HYSTERIA_B_WARMUP.as_secs(),
        measurement_duration.as_secs_f64(),
    );

    for (scenario_index, scenario) in AggregationScenario::ALL.into_iter().enumerate() {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());
        for (round_index, seeds) in seeds.iter().copied().enumerate() {
            let round = round_index + 1;
            let mut participants = base_participants.to_vec();
            let participant_count = participants.len();
            participants.rotate_left((scenario_index + round_index) % participant_count);
            if (scenario_index + round_index) % 2 == 1 {
                participants.reverse();
            }
            println!();
            println!(
                "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
                seeds.line_one,
                seeds.line_two,
                participants
                    .iter()
                    .map(|(congestion, line)| format!(
                        "{} / {}",
                        congestion.description(),
                        line.description(),
                    ))
                    .collect::<Vec<_>>()
                    .join(" → "),
            );

            for (participant_index, (congestion, line)) in participants.into_iter().enumerate() {
                apply_profiles(line_one, line_two, seeds)?;
                let payload_seed = 211_u8
                    .wrapping_add((scenario_index as u8).wrapping_mul(40))
                    .wrapping_add((round_index as u8).wrapping_mul(8))
                    .wrapping_add(participant_index as u8);
                let report = run_hysteria_throughput(
                    HysteriaThroughputConfig::new(
                        binary.clone(),
                        congestion,
                        line,
                        scenario.hysteria_bandwidth_mbps(line),
                        HYSTERIA_B_WARMUP,
                        measurement_duration,
                        HYSTERIA_B_CHUNK_SIZE,
                    )
                    .with_seed(payload_seed),
                )
                .await?;
                print_hysteria_throughput_report(&report);
                let infrastructure_pass = report.infrastructure_pass();
                observations.push(HysteriaThroughputObservation {
                    scenario,
                    round,
                    seeds,
                    payload_seed,
                    report,
                });
                write_hysteria_throughput_csv(result_path, &observations)?;
                if !infrastructure_pass {
                    return Err(lab_error(format!(
                        "Hysteria B 组基础设施门槛失败：{}第 {round} 轮 {} / {}；原始数据已保留在 {result_path}",
                        scenario.description(),
                        congestion.description(),
                        line.description(),
                    )));
                }
            }
        }
    }

    print_hysteria_b_summary(&observations);
    print_tc_statistics()?;
    println!();
    println!("Hysteria B 组原始数据已写入 {result_path}");
    if enforce_final_comparison {
        verify_hysteria_b_final_comparison(&observations)
    } else {
        Ok(())
    }
}

fn hysteria_binary_path() -> LabResult<std::path::PathBuf> {
    let path = env::var_os("FLOWWEAVE_HYSTERIA_BIN")
        .ok_or_else(|| lab_error("缺少 FLOWWEAVE_HYSTERIA_BIN；必须由准备脚本提供固定二进制"))?;
    Ok(path.into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-a-wire 在隔离网络命名空间中运行"]
async fn hysteria_a_wiring_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    let binary = hysteria_binary_path()?;
    apply_profiles(
        LinkProfile::new("20ms", "0.1%", "20mbit"),
        LinkProfile::new("80ms", "1%", "20mbit"),
        SEED_PAIRS[0],
    )?;
    let report = run_hysteria_failover(
        HysteriaFailoverConfig::new(
            binary,
            HysteriaCongestion::Bbr,
            FailoverDirection::ClientToServer,
            Duration::from_secs(3),
            Duration::from_secs(1),
            FORMAL_FAILOVER_CHUNK_SIZE,
            171,
        ),
        || {
            replace_line_profile(
                "1:1",
                "10:",
                LinkProfile::new("20ms", "100%", "20mbit"),
                SEED_PAIRS[0].line_one,
            )
        },
        || {
            replace_line_profile(
                "1:1",
                "10:",
                LinkProfile::new("20ms", "0.1%", "20mbit"),
                SEED_PAIRS[0].line_one,
            )
        },
    )
    .await?;
    print_hysteria_failover_report(&report);
    if !report.infrastructure_pass() {
        return Err(lab_error("Hysteria A 组接线诊断没有闭合"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-a-smoke 在隔离网络命名空间中运行"]
async fn hysteria_a_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-hysteria-2-9-3-a-smoke.csv";
    run_hysteria_a_matrix(RESULT_PATH, &SEED_PAIRS[..1]).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh hysteria-a-formal 在隔离网络命名空间中运行"]
async fn hysteria_a_formal_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-hysteria-2-9-3-a-formal-20.csv";
    run_hysteria_a_matrix(RESULT_PATH, &SEED_PAIRS).await
}

async fn run_hysteria_a_matrix(result_path: &str, seeds: &[NetemSeeds]) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    ensure_benchmark_paths_absent(&[result_path])?;
    let binary = hysteria_binary_path()?;
    verify_hysteria_binary(&binary)?;
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");
    let mut observations = Vec::with_capacity(
        FailoverDirection::ALL.len() * HysteriaCongestion::ALL.len() * seeds.len(),
    );
    write_hysteria_failover_csv(result_path, &observations)?;

    println!();
    println!("Hysteria 2.9.3：A 组持续 TCP 换网公平对照");
    println!("每场使用同一个应用 TCP 连接持续 30 秒，第 10 秒把主线路改为 100% 丢包。");

    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());
        for (round_index, seeds) in seeds.iter().copied().enumerate() {
            let round = round_index + 1;
            let mut participants = HysteriaCongestion::ALL.to_vec();
            if (direction_index + round_index) % 2 == 1 {
                participants.reverse();
            }
            println!();
            println!(
                "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
                seeds.line_one,
                seeds.line_two,
                participants
                    .iter()
                    .map(|participant| participant.description())
                    .collect::<Vec<_>>()
                    .join(" → ")
            );

            for congestion in participants {
                apply_profiles(normal_line_one, normal_line_two, seeds)?;
                let report = run_hysteria_failover(
                    HysteriaFailoverConfig::new(
                        binary.clone(),
                        congestion,
                        direction,
                        FORMAL_FAILOVER_DURATION,
                        FORMAL_FAILOVER_AT,
                        FORMAL_FAILOVER_CHUNK_SIZE,
                        211_u8
                            .wrapping_add(round as u8)
                            .wrapping_add((direction_index as u8).wrapping_mul(17)),
                    ),
                    || {
                        replace_line_profile(
                            "1:1",
                            "10:",
                            LinkProfile::new("20ms", "100%", "20mbit"),
                            seeds.line_one,
                        )
                    },
                    || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
                )
                .await?;
                print_hysteria_failover_report(&report);
                let infrastructure_pass = report.infrastructure_pass();
                observations.push(HysteriaFailoverObservation {
                    direction,
                    round,
                    seeds,
                    report,
                });
                write_hysteria_failover_csv(result_path, &observations)?;
                if !infrastructure_pass {
                    return Err(lab_error(format!(
                        "Hysteria A 组基础设施门槛失败：{}第 {round} 轮 {}；原始数据已保留在 {result_path}",
                        direction.description(),
                        congestion.description()
                    )));
                }
            }
        }
    }

    print_hysteria_a_summary(&observations);
    print_tc_statistics()?;
    println!();
    println!("Hysteria A 组原始数据已写入 {result_path}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh failover 在隔离网络命名空间中运行"]
async fn failover_five_seed_screening_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    const RESULT_PATH: &str = "benchmark-results/2026-07-12-pto-hedge-screening.csv";
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");
    let high_loss_line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let high_loss_line_two = LinkProfile::new("40ms", "2%", "20mbit");

    println!();
    println!("FlowWeave / 织流：A 组 PTO 对冲五种子短筛");
    println!("每轮比较同一 NoQ 版本的默认恢复与 PTO 跨路径对冲。");
    println!("每位参赛者依次接受黑洞恢复、正常网络误触发和高丢包抗误判三道题。");

    let mut observations = Vec::with_capacity(SEED_PAIRS.len() * PtoRecovery::CANDIDATES.len());
    write_recovery_screening_csv(RESULT_PATH, &observations)?;

    for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
        let round = round_index + 1;
        let order = recovery_screening_order(round_index);
        println!();
        println!(
            "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
            seeds.line_one,
            seeds.line_two,
            order
                .iter()
                .map(|candidate| candidate.description())
                .collect::<Vec<_>>()
                .join(" → "),
        );

        for pto_recovery in order {
            apply_profiles(normal_line_one, normal_line_two, seeds)?;
            let failover = run_blackhole_failover(
                MultipathScheduler::NoqDefault,
                pto_recovery,
                || {
                    replace_line_profile(
                        "1:1",
                        "10:",
                        LinkProfile::new("20ms", "100%", "20mbit"),
                        seeds.line_one,
                    )
                },
                || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
            )
            .await?;

            apply_profiles(normal_line_one, normal_line_two, seeds)?;
            let normal = run_network_benchmark(
                NetworkBenchmarkConfig::new(
                    PathMode::MultipathAvailable,
                    MultipathScheduler::NoqDefault,
                    SCREENING_TRANSFER_SIZE,
                    0,
                )
                .with_pto_recovery(pto_recovery),
            )
            .await?;

            apply_profiles(high_loss_line_one, high_loss_line_two, seeds)?;
            let high_loss = run_network_benchmark(
                NetworkBenchmarkConfig::new(
                    PathMode::MultipathAvailable,
                    MultipathScheduler::NoqDefault,
                    SCREENING_TRANSFER_SIZE,
                    0,
                )
                .with_pto_recovery(pto_recovery),
            )
            .await?;

            let observation = RecoveryScreeningObservation {
                round,
                seeds,
                pto_recovery,
                failover,
                normal,
                high_loss,
            };
            print_recovery_screening_observation(&observation);
            observations.push(observation);
            write_recovery_screening_csv(RESULT_PATH, &observations)?;
        }
    }

    print_recovery_screening_summary(&observations);
    println!();
    println!("A 组短筛原始数据已写入 {RESULT_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh formal-a 在隔离网络命名空间中运行"]
async fn failover_formal_bidirectional_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    const RESULT_PATH: &str = "benchmark-results/2026-07-12-feedback-handoff-formal-a.csv";
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("FlowWeave / 织流：关键反馈路径交接正式 A 组双向持续换网实验");
    println!("每场在同一条 QUIC 业务流上持续发送 30 秒，第 10 秒把主路改为 100% 丢包。");
    println!("接收端逐条校验序号和内容，并以故障后的最大相邻到达间隔衡量断流。");

    let mut observations = Vec::with_capacity(
        FailoverDirection::ALL.len() * SEED_PAIRS.len() * FORMAL_FAILOVER_PARTICIPANTS.len(),
    );
    write_formal_failover_csv(RESULT_PATH, &observations)?;

    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());
        for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
            let round = round_index + 1;
            let mut order = FORMAL_FAILOVER_PARTICIPANTS.to_vec();
            if (round_index + direction_index) % 2 == 1 {
                order.reverse();
            }
            println!();
            println!(
                "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
                seeds.line_one,
                seeds.line_two,
                order
                    .iter()
                    .map(|candidate| candidate.description())
                    .collect::<Vec<_>>()
                    .join(" → "),
            );

            for pto_recovery in order {
                apply_profiles(normal_line_one, normal_line_two, seeds)?;
                let report = run_sustained_blackhole_failover(
                    SustainedFailoverConfig::new(
                        MultipathScheduler::NoqDefault,
                        pto_recovery,
                        direction,
                        FORMAL_FAILOVER_DURATION,
                        FORMAL_FAILOVER_AT,
                        FORMAL_FAILOVER_CHUNK_SIZE,
                        151_u8
                            .wrapping_add(round as u8)
                            .wrapping_add((direction_index as u8).wrapping_mul(17)),
                    ),
                    || {
                        replace_line_profile(
                            "1:1",
                            "10:",
                            LinkProfile::new("20ms", "100%", "20mbit"),
                            seeds.line_one,
                        )
                    },
                    || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
                )
                .await?;

                let observation = FormalFailoverObservation {
                    direction,
                    round,
                    seeds,
                    pto_recovery,
                    report,
                };
                print_formal_failover_observation(&observation);
                observations.push(observation);
                write_formal_failover_csv(RESULT_PATH, &observations)?;
            }
        }
    }

    print_formal_failover_summary(&observations);
    println!();
    println!("正式 A 组原始数据已写入 {RESULT_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-a 在隔离网络命名空间中运行"]
async fn failover_timeline_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 3] = [
        (FailoverDirection::ClientToServer, 0_usize),
        (FailoverDirection::ClientToServer, 2_usize),
        (FailoverDirection::ServerToClient, 0_usize),
    ];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-path-ack-affinity-diagnostic.csv",
        PtoRecovery::CrossPathHedge,
        "FlowWeave / 织流：A 组 PATH_ACK 同路优先修复诊断",
        "只复跑两个正向代表种子和一个反向种子；不改变 PTO 恢复算法或超时。",
        &CASES,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-no-pto 在隔离网络命名空间中运行"]
async fn failover_no_pto_diagnostic_lab() -> LabResult<()> {
    run_seed_1103_failover_diagnostic(
        "benchmark-results/2026-07-12-no-pto-state-diagnostic-rerun.csv",
        PtoRecovery::CrossPathHedge,
        "FlowWeave / 织流：A 组无 PTO 状态时间线",
        "只复跑正向种子 1103；仅增加只读状态，不改变调度、PTO 或路径空闲上限。",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-abandon 在隔离网络命名空间中运行"]
async fn failover_abandon_reinjection_diagnostic_lab() -> LabResult<()> {
    run_seed_1103_failover_diagnostic(
        "benchmark-results/2026-07-12-abandon-reinjection-diagnostic.csv",
        PtoRecovery::CrossPathHedgeAndAbandon,
        "FlowWeave / 织流：A 组 abandoned 即时对冲诊断",
        "只复跑正向种子 1103；路径状态仍保留 3 PTO，只提前恢复未确认 STREAM 数据。",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-ack-progress 在隔离网络命名空间中运行"]
async fn failover_ack_progress_reinjection_diagnostic_lab() -> LabResult<()> {
    run_seed_1103_failover_diagnostic(
        "benchmark-results/2026-07-12-cross-path-ack-escape-diagnostic.csv",
        PtoRecovery::CrossPathRecoveryWithAckEscape,
        "FlowWeave / 织流：A 组有界跨路径 ACK 逃生诊断",
        "只复跑正向种子 1103；恢复时在备用路请求一次累计 PATH_ACK，不改变路径状态或计时器。",
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-ack-escape-representative 在隔离网络命名空间中运行"]
async fn failover_ack_escape_representative_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 2] = [
        (FailoverDirection::ClientToServer, 0_usize),
        (FailoverDirection::ServerToClient, 0_usize),
    ];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-ack-escape-representative-diagnostic.csv",
        PtoRecovery::CrossPathRecoveryWithAckEscape,
        "FlowWeave / 织流：A 组 ACK 逃生代表场诊断",
        "使用完全相同的 ACK 逃生候选复跑正向与反向种子 1101；不改算法、不调门槛。",
        &CASES,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-second-gap 在隔离网络命名空间中运行"]
async fn failover_second_gap_stream_state_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 1] = [(FailoverDirection::ClientToServer, 0_usize)];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-second-gap-stream-state-summary.csv",
        PtoRecovery::CrossPathRecoveryWithAckEscape,
        "FlowWeave / 织流：A 组第二缺口数据级状态诊断",
        "只复跑正向种子 1101；每 5 毫秒只读采集 R/H/A/Q，不改变发包、超时或线协议。",
        &CASES,
        Some("benchmark-results/2026-07-12-second-gap-stream-state-timeline.csv"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-handoff 在隔离网络命名空间中运行"]
async fn failover_feedback_handoff_representative_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 2] = [
        (FailoverDirection::ClientToServer, 0_usize),
        (FailoverDirection::ServerToClient, 0_usize),
    ];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-feedback-handoff-representative-summary.csv",
        PtoRecovery::CrossPathRecoveryWithFeedbackHandoff,
        "FlowWeave / 织流：A 组关键反馈路径交接代表场",
        "复跑正向与反向种子 1101；恢复路接管 ACK 和流控反馈，不改 PathIdle、3 PTO 或线协议。",
        &CASES,
        Some("benchmark-results/2026-07-12-feedback-handoff-representative-timeline.csv"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-handoff-1103 在隔离网络命名空间中运行"]
async fn failover_feedback_handoff_seed_1103_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 1] = [(FailoverDirection::ClientToServer, 2_usize)];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-feedback-handoff-1103-summary.csv",
        PtoRecovery::CrossPathRecoveryWithFeedbackHandoff,
        "FlowWeave / 织流：A 组关键反馈路径交接 1103 诊断",
        "只运行一次正向种子 1103；保留旧 1006.353 ms 原始数据，并采集 R/H/A/Q 验证时间预算。",
        &CASES,
        Some("benchmark-results/2026-07-12-feedback-handoff-1103-timeline.csv"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-handoff-1104 在隔离网络命名空间中运行"]
async fn failover_feedback_handoff_seed_1104_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 1] = [(FailoverDirection::ClientToServer, 3_usize)];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-feedback-handoff-1104-summary.csv",
        PtoRecovery::CrossPathRecoveryWithFeedbackHandoff,
        "FlowWeave / 织流：A 组正式失败种子 1104 状态诊断",
        "只复跑一次正向种子 1104；不改变算法和门槛，用 R/H/A/Q 定位首次恢复后的再次死锁。",
        &CASES,
        Some("benchmark-results/2026-07-12-feedback-handoff-1104-timeline.csv"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-snapshot-1104 在隔离网络命名空间中运行"]
async fn failover_feedback_snapshot_seed_1104_diagnostic_lab() -> LabResult<()> {
    const CASES: [(FailoverDirection, usize); 1] = [(FailoverDirection::ClientToServer, 3_usize)];
    run_failover_diagnostic_cases(
        "benchmark-results/2026-07-12-feedback-snapshot-1104-summary.csv",
        PtoRecovery::CrossPathRecoveryWithFeedbackSnapshot,
        "FlowWeave / 织流：在途流控快照正向种子 1104 诊断",
        "只运行一次正式失败种子 1104；验证交接瞬间已在故障路上的额度是否能由备用路接管。",
        &CASES,
        Some("benchmark-results/2026-07-12-feedback-snapshot-1104-timeline.csv"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-snapshot-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_snapshot_seed_1104_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-snapshot-1104-stability-summary.csv",
        "benchmark-results/2026-07-12-feedback-snapshot-1104-stability-timeline.csv",
        "FlowWeave / 织流：在途流控快照正向 1104 预注册稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackSnapshot,
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-snapshot-response-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_snapshot_seed_1104_response_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-snapshot-1104-response-summary.csv",
        "benchmark-results/2026-07-12-feedback-snapshot-1104-response-timeline.csv",
        "FlowWeave / 织流：正向 1104 最终响应闭环诊断矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackSnapshot,
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-probe-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_probe_seed_1104_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-probe-1104-stability-summary.csv",
        "benchmark-results/2026-07-12-feedback-probe-1104-stability-timeline.csv",
        "FlowWeave / 织流：预恢复单帧反馈探针正向 1104 预注册稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackProbe,
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-evidence-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_evidence_seed_1104_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-evidence-1104-stability-summary.csv",
        "benchmark-results/2026-07-12-feedback-evidence-1104-stability-timeline.csv",
        "FlowWeave / 织流：跨路证据驱动选择性恢复正向 1104 预注册稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackEvidence,
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-evidence-response-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_evidence_seed_1104_response_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-evidence-1104-response-v2-summary.csv",
        "benchmark-results/2026-07-12-feedback-evidence-1104-response-v2-timeline.csv",
        "FlowWeave / 织流：接收完成锚定响应预算的证据恢复正向 1104 矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackEvidence,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-gap-rescue-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_gap_rescue_seed_1104_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-gap-rescue-1104-response-v3-summary.csv",
        "benchmark-results/2026-07-12-feedback-gap-rescue-1104-response-v3-timeline.csv",
        "FlowWeave / 织流：证据恢复与有界关键缺口探针正向 1104 矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapRescue,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-feedback-gap-watch-stability 在隔离网络命名空间中运行"]
async fn failover_feedback_gap_watch_seed_1104_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-feedback-gap-watch-1104-response-v4-summary.csv",
        "benchmark-results/2026-07-12-feedback-gap-watch-1104-response-v4-timeline.csv",
        "FlowWeave / 织流：证据恢复与稳定缺口计时救援正向 1104 矩阵",
        PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-failures 在隔离网络命名空间中运行"]
async fn failover_application_progress_formal_failures_diagnostic_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-formal-failures-v6-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-formal-failures-v6-timeline.csv";
    const CANDIDATE: PtoRecovery = PtoRecovery::CrossPathRecoveryWithApplicationProgressWatch;
    // Exact v6 formal failures, including the second seed-cycle application seeds. Do not replace
    // these with the first-cycle diagnostic seeds: that would no longer reproduce the registered
    // counterexamples.
    const CASES: [(FailoverDirection, usize, usize, u8); 4] = [
        (FailoverDirection::ClientToServer, 6, 0, 183),
        (FailoverDirection::ClientToServer, 9, 3, 186),
        (FailoverDirection::ServerToClient, 8, 2, 202),
        (FailoverDirection::ServerToClient, 10, 4, 204),
    ];

    ensure_isolated_network_namespace()?;
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("FlowWeave / 织流：v6 应用义务时钟与阻塞信用逃生失败样本复刻");
    println!("只运行 v6 正式矩阵的四个失败样本；网络、时长、严格 <1000 ms 门槛均不改变。");
    println!("三场验证最老 STREAM 义务年龄；正向第 9 场验证 STREAM_DATA_BLOCKED 信用逃生。");

    let mut observations = Vec::with_capacity(CASES.len());
    write_formal_failover_csv(RESULT_PATH, &observations)?;
    write_stream_state_csv(TIMELINE_PATH, &observations)?;

    for (direction, round, seed_index, application_seed) in CASES {
        let seeds = SEED_PAIRS[seed_index];
        println!();
        println!(
            "复刻正式第 {round} 场 {}：线路种子 {}/{}，业务种子 {application_seed}",
            direction.description(),
            seeds.line_one,
            seeds.line_two,
        );
        apply_profiles(normal_line_one, normal_line_two, seeds)?;
        let report = run_sustained_blackhole_failover(
            SustainedFailoverConfig::new(
                MultipathScheduler::NoqDefault,
                CANDIDATE,
                direction,
                FORMAL_FAILOVER_DURATION,
                FORMAL_FAILOVER_AT,
                FORMAL_FAILOVER_CHUNK_SIZE,
                application_seed,
            )
            .with_stream_state_diagnostics()
            .with_receiver_anchored_response_timeout(),
            || {
                replace_line_profile(
                    "1:1",
                    "10:",
                    LinkProfile::new("20ms", "100%", "20mbit"),
                    seeds.line_one,
                )
            },
            || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
        )
        .await?;

        let observation = FormalFailoverObservation {
            direction,
            round,
            seeds,
            pto_recovery: CANDIDATE,
            report,
        };
        print_formal_failover_observation(&observation);
        observations.push(observation);
        write_formal_failover_csv(RESULT_PATH, &observations)?;
        write_stream_state_csv(TIMELINE_PATH, &observations)?;
    }

    println!();
    print_failover_persistence_profile(&observations, CANDIDATE);
    println!();
    println!("v6 四场复刻摘要已写入 {RESULT_PATH}");
    println!("v6 四场复刻状态时间线已写入 {TIMELINE_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-version-failures 在隔离网络命名空间中运行"]
async fn failover_application_progress_version_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-12-application-progress-version-v6-3-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str = "benchmark-results/2026-07-12-application-progress-version-v6-3-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.3 版本感知服务预算复刻四个 v6 正式反例",
        PtoRecovery::CrossPathRecoveryWithVersionAwareDeadline,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-reverse-8 在隔离网络命名空间中运行"]
async fn failover_stream_progress_reverse_round_8_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-v6-4-reverse-8-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-v6-4-reverse-8-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.4 数据级流进度反向第 8 轮决定性复测",
        PtoRecovery::CrossPathRecoveryWithStreamProgress,
        &[REVERSE_ROUND_8_CASE],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-failures 在隔离网络命名空间中运行"]
async fn failover_stream_progress_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-v6-4-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-v6-4-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.4 数据级流进度复测四个 v6 正式反例",
        PtoRecovery::CrossPathRecoveryWithStreamProgress,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-stability 在隔离网络命名空间中运行"]
async fn failover_stream_progress_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-v6-4-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-v6-4-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.4 数据级流进度正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithStreamProgress,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-multi-flight-budget 在隔离网络命名空间中运行"]
async fn failover_multi_flight_budget_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-multi-flight-budget-v6-5-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-multi-flight-budget-v6-5-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.5 三航次服务预算正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithMultiFlightBudget,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-multi-flight-failures 在隔离网络命名空间中运行"]
async fn failover_multi_flight_budget_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-multi-flight-budget-v6-5-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-multi-flight-budget-v6-5-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.5 三航次服务预算复测四个 v5 正式反例",
        PtoRecovery::CrossPathRecoveryWithMultiFlightBudget,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stable-multi-flight 在隔离网络命名空间中运行"]
async fn failover_stable_multi_flight_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stable-multi-flight-v6-6-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stable-multi-flight-v6-6-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.6 认证反馈稳定三航次预算正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithStableMultiFlightBudget,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stable-multi-flight-failures 在隔离网络命名空间中运行"]
async fn failover_stable_multi_flight_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stable-multi-flight-v6-6-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stable-multi-flight-v6-6-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.6 认证反馈稳定三航次预算复测四个 v5 正式反例",
        PtoRecovery::CrossPathRecoveryWithStableMultiFlightBudget,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stable-multi-flight-stability 在隔离网络命名空间中运行"]
async fn failover_stable_multi_flight_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stable-multi-flight-v6-6-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stable-multi-flight-v6-6-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.6 认证反馈稳定三航次预算正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithStableMultiFlightBudget,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-delivery-gap-watch-reverse-8 在隔离网络命名空间中运行"]
async fn failover_delivery_gap_watch_reverse_round_8_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-reverse-8-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-reverse-8-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.7 重传交付缺口监视反向第 8 轮决定性复测",
        PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch,
        &[REVERSE_ROUND_8_CASE],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-delivery-gap-watch 在隔离网络命名空间中运行"]
async fn failover_delivery_gap_watch_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.7 重传交付缺口监视正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-delivery-gap-watch-failures 在隔离网络命名空间中运行"]
async fn failover_delivery_gap_watch_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.7 重传交付缺口监视复测四个 v5 正式反例",
        PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-delivery-gap-watch-stability 在隔离网络命名空间中运行"]
async fn failover_delivery_gap_watch_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-delivery-gap-watch-v6-7-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.7 重传交付缺口监视正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-alternative-stability-reverse-8 在隔离网络命名空间中运行"]
async fn failover_alternative_stability_reverse_round_8_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-reverse-8-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-reverse-8-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.8 替代目标持续领先门控反向第 8 轮决定性复测",
        PtoRecovery::CrossPathRecoveryWithAlternativeStability,
        &[REVERSE_ROUND_8_CASE],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-alternative-stability 在隔离网络命名空间中运行"]
async fn failover_alternative_stability_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.8 替代目标持续领先门控正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithAlternativeStability,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-alternative-stability-failures 在隔离网络命名空间中运行"]
async fn failover_alternative_stability_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.8 替代目标持续领先门控复测四个 v5 正式反例",
        PtoRecovery::CrossPathRecoveryWithAlternativeStability,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-alternative-stability-stability 在隔离网络命名空间中运行"]
async fn failover_alternative_stability_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.8 替代目标持续领先门控正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithAlternativeStability,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-alternative-stability-formal 在隔离网络命名空间中运行"]
async fn failover_alternative_stability_formal_bidirectional_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-formal-20-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-alternative-stability-v6-8-formal-20-timeline.csv";
    const REPETITIONS_PER_DIRECTION: usize = 10;
    const CANDIDATE: PtoRecovery = PtoRecovery::CrossPathRecoveryWithAlternativeStability;

    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    ensure_isolated_network_namespace()?;

    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("FlowWeave / 织流：v6.8 替代目标持续领先门控正式双向矩阵");
    println!(
        "正反向各完整运行 {REPETITIONS_PER_DIRECTION} 场；五组线路种子依次循环两次，所有结果均保留。"
    );
    println!(
        "预注册门槛：每个方向 10/10 数据完整、最终响应闭环、恢复，且每场断流严格小于 1000 ms。"
    );
    println!("附加方向门槛：健康备用路不得产生 ACK-progress 超时、探针、尝试或重注。");

    let expected_samples = FailoverDirection::ALL.len() * REPETITIONS_PER_DIRECTION;
    let mut observations = Vec::with_capacity(expected_samples);
    write_formal_failover_csv(RESULT_PATH, &observations)?;
    write_stream_state_csv(TIMELINE_PATH, &observations)?;

    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());

        for repetition in 1..=REPETITIONS_PER_DIRECTION {
            let seed_index = (repetition - 1) % SEED_PAIRS.len();
            let seed_cycle = (repetition - 1) / SEED_PAIRS.len();
            let seeds = SEED_PAIRS[seed_index];
            let application_seed = 151_u8
                .wrapping_add((seed_index + 1) as u8)
                .wrapping_add((direction_index as u8).wrapping_mul(17))
                .wrapping_add((seed_cycle as u8).wrapping_mul(31));

            println!();
            println!(
                "正式重复 {repetition}/{REPETITIONS_PER_DIRECTION}：线路一种子 {}，线路二种子 {}，业务种子 {application_seed}",
                seeds.line_one, seeds.line_two
            );

            apply_profiles(normal_line_one, normal_line_two, seeds)?;
            let report = run_sustained_blackhole_failover(
                SustainedFailoverConfig::new(
                    MultipathScheduler::NoqDefault,
                    CANDIDATE,
                    direction,
                    FORMAL_FAILOVER_DURATION,
                    FORMAL_FAILOVER_AT,
                    FORMAL_FAILOVER_CHUNK_SIZE,
                    application_seed,
                )
                .with_stream_state_diagnostics()
                .with_receiver_anchored_response_timeout(),
                || {
                    replace_line_profile(
                        "1:1",
                        "10:",
                        LinkProfile::new("20ms", "100%", "20mbit"),
                        seeds.line_one,
                    )
                },
                || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
            )
            .await?;

            let observation = FormalFailoverObservation {
                direction,
                round: repetition,
                seeds,
                pto_recovery: CANDIDATE,
                report,
            };
            print_formal_failover_observation(&observation);
            observations.push(observation);
            write_formal_failover_csv(RESULT_PATH, &observations)?;
            write_stream_state_csv(TIMELINE_PATH, &observations)?;
        }
    }

    verify_stable_multi_flight_gate(&observations, CANDIDATE, expected_samples)?;
    print_candidate_only_formal_failover_summary(
        &observations,
        CANDIDATE,
        REPETITIONS_PER_DIRECTION,
    );
    println!();
    println!("v6.8 正式双向矩阵原始摘要已写入 {RESULT_PATH}");
    println!("v6.8 正式双向矩阵流控时间线已写入 {TIMELINE_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-snapshot-forward-10 在隔离网络命名空间中运行"]
async fn failover_stream_progress_snapshot_forward_round_10_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-forward-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-forward-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.9 在途流进度快照正式正向第 10 场决定性复测",
        PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot,
        &[FORWARD_FORMAL_ROUND_10_CASE],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-snapshot 在隔离网络命名空间中运行"]
async fn failover_stream_progress_snapshot_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.9 在途流进度快照正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-snapshot-failures 在隔离网络命名空间中运行"]
async fn failover_stream_progress_snapshot_formal_failures_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-formal-failures-4-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-formal-failures-4-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_application_progress_formal_failure_cases(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.9 在途流进度快照复测四个 v5 正式反例",
        PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot,
        &FORMAL_APPLICATION_PROGRESS_FAILURE_CASES,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-snapshot-stability 在隔离网络命名空间中运行"]
async fn failover_stream_progress_snapshot_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.9 在途流进度快照正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-stream-progress-snapshot-formal 在隔离网络命名空间中运行"]
async fn failover_stream_progress_snapshot_formal_bidirectional_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-formal-20-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-stream-progress-snapshot-v6-9-formal-20-timeline.csv";
    const REPETITIONS_PER_DIRECTION: usize = 10;
    const CANDIDATE: PtoRecovery = PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot;

    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    ensure_isolated_network_namespace()?;

    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("FlowWeave / 织流：v6.9 在途流进度快照正式双向矩阵");
    println!(
        "正反向各完整运行 {REPETITIONS_PER_DIRECTION} 场；五组线路种子依次循环两次，所有结果均保留。"
    );
    println!(
        "预注册门槛：每个方向 10/10 数据完整、最终响应闭环、恢复，且每场断流严格小于 1000 ms。"
    );
    println!("附加方向门槛：健康备用路不得产生 ACK-progress 超时、探针、尝试或重注。");

    let expected_samples = FailoverDirection::ALL.len() * REPETITIONS_PER_DIRECTION;
    let mut observations = Vec::with_capacity(expected_samples);
    write_formal_failover_csv(RESULT_PATH, &observations)?;
    write_stream_state_csv(TIMELINE_PATH, &observations)?;

    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());

        for repetition in 1..=REPETITIONS_PER_DIRECTION {
            let seed_index = (repetition - 1) % SEED_PAIRS.len();
            let seed_cycle = (repetition - 1) / SEED_PAIRS.len();
            let seeds = SEED_PAIRS[seed_index];
            let application_seed = 151_u8
                .wrapping_add((seed_index + 1) as u8)
                .wrapping_add((direction_index as u8).wrapping_mul(17))
                .wrapping_add((seed_cycle as u8).wrapping_mul(31));

            println!();
            println!(
                "正式重复 {repetition}/{REPETITIONS_PER_DIRECTION}：线路一种子 {}，线路二种子 {}，业务种子 {application_seed}",
                seeds.line_one, seeds.line_two
            );

            apply_profiles(normal_line_one, normal_line_two, seeds)?;
            let report = run_sustained_blackhole_failover(
                SustainedFailoverConfig::new(
                    MultipathScheduler::NoqDefault,
                    CANDIDATE,
                    direction,
                    FORMAL_FAILOVER_DURATION,
                    FORMAL_FAILOVER_AT,
                    FORMAL_FAILOVER_CHUNK_SIZE,
                    application_seed,
                )
                .with_stream_state_diagnostics()
                .with_receiver_anchored_response_timeout(),
                || {
                    replace_line_profile(
                        "1:1",
                        "10:",
                        LinkProfile::new("20ms", "100%", "20mbit"),
                        seeds.line_one,
                    )
                },
                || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
            )
            .await?;

            let observation = FormalFailoverObservation {
                direction,
                round: repetition,
                seeds,
                pto_recovery: CANDIDATE,
                report,
            };
            print_formal_failover_observation(&observation);
            observations.push(observation);
            write_formal_failover_csv(RESULT_PATH, &observations)?;
            write_stream_state_csv(TIMELINE_PATH, &observations)?;
        }
    }

    verify_stable_multi_flight_gate(&observations, CANDIDATE, expected_samples)?;
    print_candidate_only_formal_failover_summary(
        &observations,
        CANDIDATE,
        REPETITIONS_PER_DIRECTION,
    );
    println!();
    println!("v6.9 正式双向矩阵原始摘要已写入 {RESULT_PATH}");
    println!("v6.9 正式双向矩阵流控时间线已写入 {TIMELINE_PATH}");
    Ok(())
}

async fn run_application_progress_formal_failure_cases(
    result_path: &str,
    timeline_path: &str,
    title: &str,
    candidate: PtoRecovery,
    cases: &[(FailoverDirection, usize, usize, u8)],
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    if cases.is_empty() {
        return Err(lab_error("应用进展反例复测至少需要一个样本"));
    }
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("{title}");
    println!(
        "运行 v6 正式矩阵中选定的 {} 个失败样本；网络、时长、严格 <1000 ms 门槛均不改变。",
        cases.len(),
    );
    println!("同时保留反馈版本年龄与双向替代路径资格，检查恢复方向是否单调。");

    let mut observations = Vec::with_capacity(cases.len());
    write_formal_failover_csv(result_path, &observations)?;
    write_stream_state_csv(timeline_path, &observations)?;

    for &(direction, round, seed_index, application_seed) in cases {
        let seeds = SEED_PAIRS[seed_index];
        println!();
        println!(
            "复刻正式第 {round} 场 {}：线路种子 {}/{}，业务种子 {application_seed}",
            direction.description(),
            seeds.line_one,
            seeds.line_two,
        );
        apply_profiles(normal_line_one, normal_line_two, seeds)?;
        let report = run_sustained_blackhole_failover(
            SustainedFailoverConfig::new(
                MultipathScheduler::NoqDefault,
                candidate,
                direction,
                FORMAL_FAILOVER_DURATION,
                FORMAL_FAILOVER_AT,
                FORMAL_FAILOVER_CHUNK_SIZE,
                application_seed,
            )
            .with_stream_state_diagnostics()
            .with_receiver_anchored_response_timeout(),
            || {
                replace_line_profile(
                    "1:1",
                    "10:",
                    LinkProfile::new("20ms", "100%", "20mbit"),
                    seeds.line_one,
                )
            },
            || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
        )
        .await?;

        let observation = FormalFailoverObservation {
            direction,
            round,
            seeds,
            pto_recovery: candidate,
            report,
        };
        print_formal_failover_observation(&observation);
        observations.push(observation);
        write_formal_failover_csv(result_path, &observations)?;
        write_stream_state_csv(timeline_path, &observations)?;
    }

    verify_stable_multi_flight_gate(&observations, candidate, cases.len())?;

    println!();
    print_failover_persistence_profile(&observations, candidate);
    println!();
    println!("反例复刻摘要已写入 {result_path}");
    println!("反例复刻状态时间线已写入 {timeline_path}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-stability 在隔离网络命名空间中运行"]
async fn failover_application_progress_seed_1104_stability_lab() -> LabResult<()> {
    run_feedback_snapshot_seed_1104_stability_matrix(
        "benchmark-results/2026-07-12-application-progress-1104-stability-v6-summary.csv",
        "benchmark-results/2026-07-12-application-progress-1104-stability-v6-timeline.csv",
        "FlowWeave / 织流：v6 应用义务时钟与阻塞信用逃生正向 1104 稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithApplicationProgressWatch,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-age 在隔离网络命名空间中运行"]
async fn failover_application_progress_age_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-age-v6-1-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-age-v6-1-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.1 原始发送年龄继承正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithApplicationProgressWatch,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-age-stability 在隔离网络命名空间中运行"]
async fn failover_application_progress_age_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-age-v6-1-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-age-v6-1-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.1 原始发送年龄继承正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithApplicationProgressWatch,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-deadline 在隔离网络命名空间中运行"]
async fn failover_application_progress_deadline_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-deadline-v6-2-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-deadline-v6-2-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.2 跨副本义务刷新与一秒服务预算正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithApplicationProgressDeadline,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-deadline-stability 在隔离网络命名空间中运行"]
async fn failover_application_progress_deadline_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-deadline-v6-2-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-deadline-v6-2-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.2 跨副本义务刷新与一秒服务预算正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithApplicationProgressDeadline,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-version 在隔离网络命名空间中运行"]
async fn failover_application_progress_version_seed_1104_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-version-v6-3-smoke-3-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-version-v6-3-smoke-3-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.3 反馈版本单调恢复正向 1104 三轮探针",
        PtoRecovery::CrossPathRecoveryWithVersionAwareDeadline,
        true,
        3,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh diagnose-application-progress-version-stability 在隔离网络命名空间中运行"]
async fn failover_application_progress_version_seed_1104_stability_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-version-v6-3-stability-10-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-application-progress-version-v6-3-stability-10-timeline.csv";
    ensure_benchmark_paths_absent(&[RESULT_PATH, TIMELINE_PATH])?;
    run_feedback_snapshot_seed_1104_stability_matrix(
        RESULT_PATH,
        TIMELINE_PATH,
        "FlowWeave / 织流：v6.3 反馈版本单调恢复正向 1104 十轮稳定性矩阵",
        PtoRecovery::CrossPathRecoveryWithVersionAwareDeadline,
        true,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh formal-gap-watch 在隔离网络命名空间中运行"]
async fn failover_feedback_gap_watch_formal_bidirectional_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-feedback-gap-watch-formal-v6-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-feedback-gap-watch-formal-v6-timeline.csv";
    const REPETITIONS_PER_DIRECTION: usize = 10;
    const CANDIDATE: PtoRecovery = PtoRecovery::CrossPathRecoveryWithFeedbackEvidenceAndGapWatch;

    ensure_isolated_network_namespace()?;

    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("FlowWeave / 织流：证据恢复与稳定缺口计时救援正式双向矩阵");
    println!(
        "正反向各完整运行 {REPETITIONS_PER_DIRECTION} 场；五组线路种子依次循环两次，所有结果均保留。"
    );
    println!(
        "预注册门槛：每个方向 10/10 数据完整、最终响应闭环、恢复，且每场断流严格小于 1000 ms。"
    );
    println!("响应预算从接收端确认完整收到请求时开始；15 秒上限和网络参数均不放宽。");

    let mut observations =
        Vec::with_capacity(FailoverDirection::ALL.len() * REPETITIONS_PER_DIRECTION);
    write_formal_failover_csv(RESULT_PATH, &observations)?;
    write_stream_state_csv(TIMELINE_PATH, &observations)?;

    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());

        for repetition in 1..=REPETITIONS_PER_DIRECTION {
            let seed_index = (repetition - 1) % SEED_PAIRS.len();
            let seed_cycle = (repetition - 1) / SEED_PAIRS.len();
            let seeds = SEED_PAIRS[seed_index];
            let application_seed = 151_u8
                .wrapping_add((seed_index + 1) as u8)
                .wrapping_add((direction_index as u8).wrapping_mul(17))
                .wrapping_add((seed_cycle as u8).wrapping_mul(31));

            println!();
            println!(
                "正式重复 {repetition}/{REPETITIONS_PER_DIRECTION}：线路一种子 {}，线路二种子 {}，业务种子 {application_seed}",
                seeds.line_one, seeds.line_two
            );

            apply_profiles(normal_line_one, normal_line_two, seeds)?;
            let report = run_sustained_blackhole_failover(
                SustainedFailoverConfig::new(
                    MultipathScheduler::NoqDefault,
                    CANDIDATE,
                    direction,
                    FORMAL_FAILOVER_DURATION,
                    FORMAL_FAILOVER_AT,
                    FORMAL_FAILOVER_CHUNK_SIZE,
                    application_seed,
                )
                .with_stream_state_diagnostics()
                .with_receiver_anchored_response_timeout(),
                || {
                    replace_line_profile(
                        "1:1",
                        "10:",
                        LinkProfile::new("20ms", "100%", "20mbit"),
                        seeds.line_one,
                    )
                },
                || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
            )
            .await?;

            let observation = FormalFailoverObservation {
                direction,
                round: repetition,
                seeds,
                pto_recovery: CANDIDATE,
                report,
            };
            print_formal_failover_observation(&observation);
            observations.push(observation);
            write_formal_failover_csv(RESULT_PATH, &observations)?;
            write_stream_state_csv(TIMELINE_PATH, &observations)?;
        }
    }

    print_candidate_only_formal_failover_summary(
        &observations,
        CANDIDATE,
        REPETITIONS_PER_DIRECTION,
    );
    println!();
    println!("正式双向矩阵原始摘要已写入 {RESULT_PATH}");
    println!("正式双向矩阵流控时间线已写入 {TIMELINE_PATH}");
    Ok(())
}

async fn run_feedback_snapshot_seed_1104_stability_matrix(
    result_path: &str,
    timeline_path: &str,
    title: &str,
    pto_recovery: PtoRecovery,
    receiver_anchored_response_timeout: bool,
) -> LabResult<()> {
    run_feedback_snapshot_seed_1104_matrix(
        result_path,
        timeline_path,
        title,
        pto_recovery,
        receiver_anchored_response_timeout,
        10,
    )
    .await
}

async fn run_feedback_snapshot_seed_1104_matrix(
    result_path: &str,
    timeline_path: &str,
    title: &str,
    pto_recovery: PtoRecovery,
    receiver_anchored_response_timeout: bool,
    repetitions: usize,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;
    if repetitions == 0 {
        return Err(lab_error("稳定性矩阵至少需要一次重复"));
    }

    const SEED_INDEX: usize = 3;
    let direction = FailoverDirection::ClientToServer;
    let seeds = SEED_PAIRS[SEED_INDEX];
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");
    let application_seed = 151_u8.wrapping_add((SEED_INDEX + 1) as u8);

    println!();
    println!("{title}");
    println!("固定线路种子、业务种子、方向和算法，完整保留 {repetitions} 次结果；不挑样本。");

    let mut observations = Vec::with_capacity(repetitions);
    write_formal_failover_csv(result_path, &observations)?;
    write_stream_state_csv(timeline_path, &observations)?;

    for repetition in 1..=repetitions {
        println!();
        println!(
            "稳定性重复 {repetition}/{repetitions}：线路一种子 {}，线路二种子 {}",
            seeds.line_one, seeds.line_two
        );
        apply_profiles(normal_line_one, normal_line_two, seeds)?;
        let mut config = SustainedFailoverConfig::new(
            MultipathScheduler::NoqDefault,
            pto_recovery,
            direction,
            FORMAL_FAILOVER_DURATION,
            FORMAL_FAILOVER_AT,
            FORMAL_FAILOVER_CHUNK_SIZE,
            application_seed,
        )
        .with_stream_state_diagnostics();
        if receiver_anchored_response_timeout {
            config = config.with_receiver_anchored_response_timeout();
        }
        let report = run_sustained_blackhole_failover(
            config,
            || {
                replace_line_profile(
                    "1:1",
                    "10:",
                    LinkProfile::new("20ms", "100%", "20mbit"),
                    seeds.line_one,
                )
            },
            || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
        )
        .await?;

        let observation = FormalFailoverObservation {
            direction,
            round: repetition,
            seeds,
            pto_recovery,
            report,
        };
        print_formal_failover_observation(&observation);
        observations.push(observation);
        write_formal_failover_csv(result_path, &observations)?;
        write_stream_state_csv(timeline_path, &observations)?;
    }

    verify_stable_multi_flight_gate(&observations, pto_recovery, repetitions)?;

    println!();
    print_failover_persistence_profile(&observations, pto_recovery);
    println!();
    println!("稳定性矩阵原始摘要已写入 {result_path}");
    println!("稳定性矩阵流控时间线已写入 {timeline_path}");
    Ok(())
}

async fn run_failover_diagnostic_cases(
    result_path: &str,
    pto_recovery: PtoRecovery,
    title: &str,
    note: &str,
    cases: &[(FailoverDirection, usize)],
    stream_state_path: Option<&str>,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("{title}");
    println!("{note}");

    let mut observations = Vec::with_capacity(cases.len());
    write_formal_failover_csv(result_path, &observations)?;
    if let Some(path) = stream_state_path {
        write_stream_state_csv(path, &observations)?;
    }
    for &(direction, seed_index) in cases {
        let seeds = SEED_PAIRS[seed_index];
        let round = seed_index + 1;
        println!();
        println!(
            "诊断 {} 第 {round} 轮：线路一种子 {}，线路二种子 {}",
            direction.description(),
            seeds.line_one,
            seeds.line_two,
        );
        apply_profiles(normal_line_one, normal_line_two, seeds)?;
        let mut config = SustainedFailoverConfig::new(
            MultipathScheduler::NoqDefault,
            pto_recovery,
            direction,
            FORMAL_FAILOVER_DURATION,
            FORMAL_FAILOVER_AT,
            FORMAL_FAILOVER_CHUNK_SIZE,
            151_u8
                .wrapping_add(round as u8)
                .wrapping_add((direction as u8).wrapping_mul(17)),
        );
        if stream_state_path.is_some() {
            config = config.with_stream_state_diagnostics();
        }
        let report = run_sustained_blackhole_failover(
            config,
            || {
                replace_line_profile(
                    "1:1",
                    "10:",
                    LinkProfile::new("20ms", "100%", "20mbit"),
                    seeds.line_one,
                )
            },
            || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
        )
        .await?;

        let observation = FormalFailoverObservation {
            direction,
            round,
            seeds,
            pto_recovery,
            report,
        };
        print_formal_failover_observation(&observation);
        observations.push(observation);
        write_formal_failover_csv(result_path, &observations)?;
        if let Some(path) = stream_state_path {
            write_stream_state_csv(path, &observations)?;
        }
    }

    println!();
    println!("诊断原始数据已写入 {result_path}");
    if let Some(path) = stream_state_path {
        println!("数据级状态时间线已写入 {path}");
    }
    Ok(())
}

async fn run_seed_1103_failover_diagnostic(
    result_path: &str,
    pto_recovery: PtoRecovery,
    title: &str,
    note: &str,
) -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    const SEED_INDEX: usize = 2;
    let direction = FailoverDirection::ClientToServer;
    let seeds = SEED_PAIRS[SEED_INDEX];
    let round = SEED_INDEX + 1;
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("{title}");
    println!("{note}");

    let mut observations = Vec::with_capacity(1);
    write_formal_failover_csv(result_path, &observations)?;
    apply_profiles(normal_line_one, normal_line_two, seeds)?;
    let report = run_sustained_blackhole_failover(
        SustainedFailoverConfig::new(
            MultipathScheduler::NoqDefault,
            pto_recovery,
            direction,
            FORMAL_FAILOVER_DURATION,
            FORMAL_FAILOVER_AT,
            FORMAL_FAILOVER_CHUNK_SIZE,
            151_u8.wrapping_add(round as u8),
        ),
        || {
            replace_line_profile(
                "1:1",
                "10:",
                LinkProfile::new("20ms", "100%", "20mbit"),
                seeds.line_one,
            )
        },
        || replace_line_profile("1:1", "10:", normal_line_one, seeds.line_one),
    )
    .await?;

    let observation = FormalFailoverObservation {
        direction,
        round,
        seeds,
        pto_recovery,
        report,
    };
    print_formal_failover_observation(&observation);
    observations.push(observation);
    write_formal_failover_csv(result_path, &observations)?;

    println!();
    println!("单场诊断原始数据已写入 {result_path}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh screen 在隔离网络命名空间中运行"]
async fn scheduler_five_seed_screening_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    const RESULT_PATH: &str = "benchmark-results/2026-07-11-scheduler-screening-survivors.csv";
    println!();
    println!("FlowWeave / 织流：多路径调度五种子筛选");
    println!("这是 2 MiB 候选筛选，不是 BENCHMARK.md 规定的 20 秒/64 MiB 最终验收。");
    println!("每位参赛者每轮都重置到相同种子；轮次会旋转并反转参赛顺序。");

    let mut observations = Vec::with_capacity(
        AggregationScenario::ALL.len() * SEED_PAIRS.len() * ScreeningParticipant::ALL.len(),
    );

    for scenario in AggregationScenario::ALL {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());

        for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
            let round = round_index + 1;
            let order = screening_order(round_index);
            println!();
            println!(
                "第 {round} 轮：线路一种子 {}，线路二种子 {}",
                seeds.line_one, seeds.line_two
            );
            println!(
                "参赛顺序：{}",
                order
                    .iter()
                    .map(|participant| participant.description())
                    .collect::<Vec<_>>()
                    .join(" → ")
            );

            for participant in order {
                apply_profiles(line_one, line_two, seeds)?;
                let report = run_network_benchmark(participant.config()).await?;
                print_screening_observation(participant, &report);
                observations.push(ScreeningObservation {
                    scenario,
                    round,
                    seeds,
                    participant,
                    report,
                });
            }
        }
    }

    print_screening_summary(&observations);
    write_benchmark_csv(RESULT_PATH, &observations)?;
    println!();
    println!("原始数据已写入 {RESULT_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh long 在隔离网络命名空间中运行"]
async fn scheduler_long_duration_benchmark_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    const RESULT_PATH: &str = "benchmark-results/2026-07-11-scheduler-long-survivors.csv";
    println!();
    println!("FlowWeave / 织流：B 组长时聚合复赛");
    println!(
        "每次连接预热 {} 秒，再计时至少 {} 秒；使用 release 构建、5 对固定种子和交替顺序。",
        LONG_WARMUP_DURATION.as_secs(),
        LONG_MEASUREMENT_DURATION.as_secs(),
    );
    println!("参赛者：两条单路、NoQ 默认；当前没有通过筛选的自定义候选。");

    let mut observations = Vec::with_capacity(
        AggregationScenario::ALL.len() * SEED_PAIRS.len() * ScreeningParticipant::ALL.len(),
    );
    write_benchmark_csv(RESULT_PATH, &observations)?;

    for scenario in AggregationScenario::ALL {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());

        for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
            let round = round_index + 1;
            let order = screening_order(round_index);
            println!();
            println!(
                "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
                seeds.line_one,
                seeds.line_two,
                order
                    .iter()
                    .map(|participant| participant.description())
                    .collect::<Vec<_>>()
                    .join(" → "),
            );

            for participant in order {
                apply_profiles(line_one, line_two, seeds)?;
                let report =
                    run_sustained_network_benchmark(participant.sustained_config()).await?;
                print_screening_observation(participant, &report);
                observations.push(ScreeningObservation {
                    scenario,
                    round,
                    seeds,
                    participant,
                    report,
                });
                write_benchmark_csv(RESULT_PATH, &observations)?;
            }
        }
    }

    print_screening_summary(&observations);
    println!();
    println!("长时复赛原始数据已写入 {RESULT_PATH}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh b-controller-gate 在隔离网络命名空间中运行"]
async fn b_noq_bbr3_controller_gate_v1_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-b-noq-bbr3-controller-gate-v1-smoke.csv";

    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    ensure_isolated_network_namespace()?;

    let seeds = SEED_PAIRS[0];
    let mut observations =
        Vec::with_capacity(AggregationScenario::ALL.len() * BControllerParticipant::ALL.len());
    write_b_controller_csv(RESULT_PATH, &observations)?;

    println!();
    println!("FlowWeave / 织流：NoQ 默认 + BBR3 最小控制器门控 v1");
    println!(
        "首种子；每项预热 {} 秒、测量 {} 秒、应用块 {} KiB；固定顺序运行六项。",
        B_CONTROLLER_GATE_WARMUP.as_secs(),
        B_CONTROLLER_GATE_MEASUREMENT.as_secs(),
        B_CONTROLLER_GATE_CHUNK_SIZE / KIB,
    );

    for scenario in AggregationScenario::ALL {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());

        for participant in BControllerParticipant::ALL {
            apply_profiles(line_one, line_two, seeds)?;
            let report = run_sustained_network_benchmark(participant.config()).await?;
            observations.push(BControllerObservation {
                scenario,
                seeds,
                participant,
                report,
            });
            print_b_controller_observation(
                observations.last().expect("刚插入的门控观测必须存在"),
                &observations,
            );
            write_b_controller_csv(RESULT_PATH, &observations)?;
        }
    }

    print_b_controller_summary(&observations);
    println!();
    println!("门控原始数据已写入 {RESULT_PATH}");
    verify_b_controller_gate(&observations)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh b-declared-epoch 在隔离网络命名空间中运行"]
async fn b_declared_backlogged_epoch_v1_smoke_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-13-b-declared-backlogged-epoch-v1-smoke.csv";

    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    ensure_isolated_network_namespace()?;

    let seeds = SEED_PAIRS[0];
    let mut observations =
        Vec::with_capacity(AggregationScenario::ALL.len() * BDeclaredEpochParticipant::ALL.len());
    write_b_declared_epoch_csv(RESULT_PATH, &observations)?;

    println!();
    println!("FlowWeave / 织流：应用外生声明 backlogged epoch 传感器 v1");
    println!(
        "首种子；持续单流预热 {} 秒、无条件测量 {} 秒、记录 {} KiB、固定 {} 个 cohort；结束后等待 1500 ms 结算。",
        B_DECLARED_EPOCH_WARMUP.as_secs(),
        B_DECLARED_EPOCH_MEASUREMENT.as_secs(),
        B_DECLARED_EPOCH_CHUNK_SIZE / KIB,
        B_DECLARED_EPOCH_COHORTS,
    );

    for scenario in AggregationScenario::ALL {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());
        for participant in BDeclaredEpochParticipant::ALL {
            apply_profiles(line_one, line_two, seeds)?;
            let report = run_declared_backlogged_epoch_probe(participant.config()).await?;
            observations.push(BDeclaredEpochObservation {
                scenario,
                seeds,
                participant,
                report,
            });
            let observation = observations
                .last()
                .expect("刚插入的外生 epoch 观测必须存在");
            print_b_declared_epoch_observation(observation, &observations);
            write_b_declared_epoch_csv(RESULT_PATH, &observations)?;
        }
    }

    print_b_declared_epoch_summary(&observations);
    println!();
    println!("外生 epoch 传感器原始数据已写入 {RESULT_PATH}");
    verify_b_declared_epoch_gate(&observations)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh b-continuous-formal 在隔离网络命名空间中运行"]
async fn b_cubic_noq_continuous_formal_v1_lab() -> LabResult<()> {
    const RESULT_PATH: &str = "benchmark-results/2026-07-13-b-cubic-noq-continuous-formal-v1.csv";

    ensure_benchmark_paths_absent(&[RESULT_PATH])?;
    ensure_isolated_network_namespace()?;

    let mut observations = Vec::with_capacity(
        AggregationScenario::ALL.len() * SEED_PAIRS.len() * BContinuousParticipant::ALL.len(),
    );
    write_b_continuous_csv(RESULT_PATH, &observations)?;

    println!();
    println!("FlowWeave / 织流：Cubic + NoQ 持续单流正式 B 门控 v1");
    println!(
        "两个锁定场景、五对固定种子；同一 STREAM 预热 {} 秒后由接收端连续计时 {} 秒，记录 {} KiB。",
        B_CONTINUOUS_FORMAL_WARMUP.as_secs(),
        B_CONTINUOUS_FORMAL_MEASUREMENT.as_secs(),
        B_CONTINUOUS_FORMAL_CHUNK_SIZE / KIB,
    );
    println!(
        "逐轮门槛：双路 >= 最佳单路 {:.0}%，两路首次数据各 >= {:.0}%，UDP/应用 <= {:.2}x；每场至少 4/5。",
        B_CONTINUOUS_FORMAL_GAIN_RATIO * 100.0,
        B_CONTINUOUS_FORMAL_MINIMUM_SHARE_PERCENT,
        B_CONTINUOUS_FORMAL_WIRE_RATIO_LIMIT,
    );

    for scenario in AggregationScenario::ALL {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());

        for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
            let round = round_index + 1;
            let order = b_continuous_order(round_index);
            println!();
            println!(
                "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
                seeds.line_one,
                seeds.line_two,
                order
                    .iter()
                    .map(|participant| participant.description())
                    .collect::<Vec<_>>()
                    .join(" → "),
            );

            for participant in order {
                apply_profiles(line_one, line_two, seeds)?;
                let report = run_continuous_network_benchmark(participant.config()).await?;
                observations.push(BContinuousObservation {
                    scenario,
                    round,
                    seeds,
                    participant,
                    report,
                });
                let observation = observations.last().expect("刚插入的持续单流观测必须存在");
                print_b_continuous_observation(observation, &observations);
                write_b_continuous_csv(RESULT_PATH, &observations)?;
            }
        }
    }

    print_b_continuous_summary(&observations);
    println!();
    println!("持续单流正式 B 原始数据已写入 {RESULT_PATH}");
    verify_b_continuous_formal(&observations)
}

fn screening_order(round_index: usize) -> Vec<ScreeningParticipant> {
    let mut order = ScreeningParticipant::ALL.to_vec();
    let len = order.len();
    order.rotate_left(round_index % len);
    if round_index % 2 == 1 {
        order.reverse();
    }
    order
}

fn b_continuous_order(round_index: usize) -> Vec<BContinuousParticipant> {
    let mut order = BContinuousParticipant::ALL.to_vec();
    let len = order.len();
    order.rotate_left(round_index % len);
    if round_index % 2 == 1 {
        order.reverse();
    }
    order
}

fn recovery_screening_order(round_index: usize) -> Vec<PtoRecovery> {
    let mut order = PtoRecovery::CANDIDATES.to_vec();
    if round_index % 2 == 1 {
        order.reverse();
    }
    order
}

fn print_recovery_screening_observation(observation: &RecoveryScreeningObservation) {
    let failover_udp = observation
        .failover
        .primary_bytes_after_blackhole
        .saturating_add(observation.failover.secondary_bytes_after_blackhole);
    let failover_hedges = observation
        .failover
        .primary_pto_hedges
        .saturating_add(observation.failover.secondary_pto_hedges);
    let failover_hedge_bytes = observation
        .failover
        .primary_pto_hedge_bytes
        .saturating_add(observation.failover.secondary_pto_hedge_bytes);

    println!("- {}", observation.pto_recovery.description());
    println!(
        "  黑洞：恢复 {}，首字节 {}，整段完成 {}，UDP {} 字节，对冲 {} 次 / {} 字节，主路/备用路仍开放 {} / {}",
        yes_or_no(observation.failover.recovered),
        optional_milliseconds(observation.failover.recovery_time),
        optional_milliseconds(observation.failover.completion_time),
        failover_udp,
        failover_hedges,
        failover_hedge_bytes,
        yes_or_no(observation.failover.primary_path_open),
        yes_or_no(observation.failover.secondary_path_open),
    );
    println!(
        "  正常：{:.2} Mbit/s，UDP {} 字节，对冲 {} 次 / {} 字节，两路仍开放 {}",
        observation.normal.throughput_mbps,
        observation.normal.total_udp_bytes_sent,
        total_pto_hedges(&observation.normal),
        total_pto_hedge_bytes(&observation.normal),
        yes_or_no(observation.normal.all_configured_paths_open),
    );
    println!(
        "  高丢包：{:.2} Mbit/s，UDP {} 字节，对冲 {} 次 / {} 字节，至少一路仍开放 {}",
        observation.high_loss.throughput_mbps,
        observation.high_loss.total_udp_bytes_sent,
        total_pto_hedges(&observation.high_loss),
        total_pto_hedge_bytes(&observation.high_loss),
        yes_or_no(observation.high_loss.any_configured_path_open),
    );
}

fn print_recovery_screening_summary(observations: &[RecoveryScreeningObservation]) {
    let candidates: Vec<_> = observations
        .iter()
        .filter(|observation| observation.pto_recovery == PtoRecovery::CrossPathHedge)
        .collect();
    let recovered = candidates
        .iter()
        .filter(|observation| observation.failover.recovered)
        .count();
    let recovery_times: Vec<_> = candidates
        .iter()
        .filter_map(|observation| observation.failover.recovery_time)
        .map(|duration| duration.as_secs_f64() * 1_000.0)
        .collect();
    let recovery_p95 = if recovery_times.is_empty() {
        None
    } else {
        Some(NumericSummary::from_samples(recovery_times).p95)
    };

    let normal_throughput = NumericSummary::from_samples(candidates.iter().map(|candidate| {
        candidate.normal.throughput_mbps
            / matching_recovery_baseline(observations, candidate.round)
                .normal
                .throughput_mbps
            * 100.0
    }));
    let normal_udp = NumericSummary::from_samples(candidates.iter().map(|candidate| {
        candidate.normal.total_udp_bytes_sent as f64
            / matching_recovery_baseline(observations, candidate.round)
                .normal
                .total_udp_bytes_sent as f64
            * 100.0
    }));
    let high_loss_udp = NumericSummary::from_samples(candidates.iter().map(|candidate| {
        candidate.high_loss.total_udp_bytes_sent as f64
            / matching_recovery_baseline(observations, candidate.round)
                .high_loss
                .total_udp_bytes_sent as f64
            * 100.0
    }));
    let normal_paths_open = candidates
        .iter()
        .filter(|candidate| candidate.normal.all_configured_paths_open)
        .count();
    let high_loss_paths_usable = candidates
        .iter()
        .filter(|candidate| candidate.high_loss.any_configured_path_open)
        .count();
    let hedge_episodes: u64 = candidates
        .iter()
        .map(|candidate| {
            candidate
                .failover
                .primary_pto_hedges
                .saturating_add(candidate.failover.secondary_pto_hedges)
                .saturating_add(total_pto_hedges(&candidate.normal))
                .saturating_add(total_pto_hedges(&candidate.high_loss))
        })
        .sum();
    let hedge_bytes: u64 = candidates
        .iter()
        .map(|candidate| {
            candidate
                .failover
                .primary_pto_hedge_bytes
                .saturating_add(candidate.failover.secondary_pto_hedge_bytes)
                .saturating_add(total_pto_hedge_bytes(&candidate.normal))
                .saturating_add(total_pto_hedge_bytes(&candidate.high_loss))
        })
        .sum();

    let blackhole_pass = recovered == SEED_PAIRS.len()
        && recovery_p95.is_some_and(|milliseconds| milliseconds < 1_000.0);
    let normal_pass = normal_paths_open == SEED_PAIRS.len()
        && normal_throughput.median >= 95.0
        && normal_udp.median <= 105.0;
    let high_loss_pass =
        high_loss_paths_usable == SEED_PAIRS.len() && high_loss_udp.median <= 125.0;

    println!();
    println!("A 组五种子汇总：");
    println!(
        "- 黑洞恢复：{recovered}/{}，P95 {}，门槛 {}",
        SEED_PAIRS.len(),
        recovery_p95
            .map(|value| format!("{value:.2} ms"))
            .unwrap_or_else(|| "无有效样本".to_owned()),
        yes_or_no(blackhole_pass),
    );
    println!(
        "- 正常网络：吞吐相对基线中位 {:.2}%，UDP 相对基线中位 {:.2}%，两路仍开放 {normal_paths_open}/{}，门槛 {}",
        normal_throughput.median,
        normal_udp.median,
        SEED_PAIRS.len(),
        yes_or_no(normal_pass),
    );
    println!(
        "- 高丢包：UDP 相对基线中位 {:.2}%，至少一路仍开放 {high_loss_paths_usable}/{}，门槛 {}",
        high_loss_udp.median,
        SEED_PAIRS.len(),
        yes_or_no(high_loss_pass),
    );
    println!("- 候选共触发 {hedge_episodes} 次对冲，入队 STREAM 载荷 {hedge_bytes} 字节。");
    println!(
        "- PTO 对冲是否同时通过三组短筛：{}",
        yes_or_no(blackhole_pass && normal_pass && high_loss_pass),
    );
}

fn print_formal_failover_observation(observation: &FormalFailoverObservation) {
    let before_primary = &observation.report.sender_primary_before_blackhole;
    let before_secondary = &observation.report.sender_secondary_before_blackhole;
    let after_primary = &observation.report.sender_primary_after_blackhole;
    let after_secondary = &observation.report.sender_secondary_after_blackhole;
    let receiver_primary = &observation.report.receiver_primary_after_blackhole;
    let receiver_secondary = &observation.report.receiver_secondary_after_blackhole;
    let total_udp = after_primary
        .udp_bytes_sent
        .saturating_add(after_secondary.udp_bytes_sent);
    let total_hedges = after_primary
        .pto_hedges
        .saturating_add(after_secondary.pto_hedges);
    let total_hedge_bytes = after_primary
        .pto_hedge_bytes
        .saturating_add(after_secondary.pto_hedge_bytes);
    let pre_blackhole_hedges = before_primary
        .pto_hedges
        .saturating_add(before_secondary.pto_hedges);
    let pre_blackhole_hedge_bytes = before_primary
        .pto_hedge_bytes
        .saturating_add(before_secondary.pto_hedge_bytes);

    println!("- {}", observation.pto_recovery.description());
    println!(
        "  数据完整 {}，最终响应闭环 {}，恢复 {}，断流 {}，持续 {}，记录 {} 条 / {} 字节",
        yes_or_no(observation.report.data_intact),
        yes_or_no(observation.report.exchange_complete),
        yes_or_no(observation.report.recovered),
        optional_milliseconds(observation.report.recovery_gap),
        optional_milliseconds(observation.report.transfer_duration),
        observation.report.records_received,
        observation.report.application_bytes_received,
    );
    println!(
        "  黑洞前主路/备用路首次数据 {} / {} 字节，对冲 {} 次 / {} 字节；黑洞后 UDP {} 字节，对冲 {} 次 / {} 字节",
        before_primary.fresh_stream_bytes_sent,
        before_secondary.fresh_stream_bytes_sent,
        pre_blackhole_hedges,
        pre_blackhole_hedge_bytes,
        total_udp,
        total_hedges,
        total_hedge_bytes,
    );
    println!(
        "  发送端主路 loss/PTO/尝试/空尝试 {}/{}/{}/{}，最近未确认字节/包表 STREAM 帧 {}/{}；备用路 {}/{}/{}/{}",
        after_primary.loss_detection_timeouts,
        after_primary.pto_timeouts,
        after_primary.pto_recovery_attempts,
        after_primary.pto_recovery_empty_attempts,
        after_primary.last_pto_recovery_unacked_bytes,
        after_primary.last_pto_recovery_stream_frames,
        after_secondary.loss_detection_timeouts,
        after_secondary.pto_timeouts,
        after_secondary.pto_recovery_attempts,
        after_secondary.pto_recovery_empty_attempts,
    );
    println!(
        "  abandoned 即时恢复：主路尝试/空尝试/对冲/字节 {}/{}/{}/{}；备用路 {}/{}/{}/{}",
        after_primary.path_abandon_recovery_attempts,
        after_primary.path_abandon_recovery_empty_attempts,
        after_primary.path_abandon_reinjections,
        after_primary.path_abandon_reinjected_bytes,
        after_secondary.path_abandon_recovery_attempts,
        after_secondary.path_abandon_recovery_empty_attempts,
        after_secondary.path_abandon_reinjections,
        after_secondary.path_abandon_reinjected_bytes,
    );
    println!(
        "  ACK 进展恢复：主路超时/尝试/空尝试/对冲/字节 {}/{}/{}/{}/{}；备用路 {}/{}/{}/{}/{}",
        after_primary.ack_progress_recovery_timeouts,
        after_primary.ack_progress_recovery_attempts,
        after_primary.ack_progress_recovery_empty_attempts,
        after_primary.ack_progress_reinjections,
        after_primary.ack_progress_reinjected_bytes,
        after_secondary.ack_progress_recovery_timeouts,
        after_secondary.ack_progress_recovery_attempts,
        after_secondary.ack_progress_recovery_empty_attempts,
        after_secondary.ack_progress_reinjections,
        after_secondary.ack_progress_reinjected_bytes,
    );
    println!(
        "  预恢复反馈探针：主路超时/探针/字节 {}/{}/{}；备用路 {}/{}/{}；首个主路探针 {}",
        after_primary.ack_progress_feedback_probe_timeouts,
        after_primary.ack_progress_feedback_probes,
        after_primary.ack_progress_feedback_probe_bytes,
        after_secondary.ack_progress_feedback_probe_timeouts,
        after_secondary.ack_progress_feedback_probes,
        after_secondary.ack_progress_feedback_probe_bytes,
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_primary_ack_progress_feedback_probe,
        ),
    );
    println!(
        "  数据级流进度：发送端主路更新/确认字节 {}/{}，备用路 {}/{}；接收端主路 {}/{}，备用路 {}/{}",
        after_primary.stream_progress_updates,
        after_primary.stream_progress_acked_bytes,
        after_secondary.stream_progress_updates,
        after_secondary.stream_progress_acked_bytes,
        receiver_primary.stream_progress_updates,
        receiver_primary.stream_progress_acked_bytes,
        receiver_secondary.stream_progress_updates,
        receiver_secondary.stream_progress_acked_bytes,
    );
    println!(
        "  关键缺口探针：主路探针/触发字节 {}/{}；备用路 {}/{}",
        after_primary.stream_gap_rescue_probes,
        after_primary.stream_gap_rescue_bytes,
        after_secondary.stream_gap_rescue_probes,
        after_secondary.stream_gap_rescue_bytes,
    );
    println!(
        "  接收端阻塞信用逃生：主路 handoff/MAX_DATA/MAX_STREAM_DATA {}/{}/{}；备用路 {}/{}/{}",
        receiver_primary.blocked_credit_handoffs,
        receiver_primary.blocked_credit_max_data_requeues,
        receiver_primary.blocked_credit_max_stream_data_requeues,
        receiver_secondary.blocked_credit_handoffs,
        receiver_secondary.blocked_credit_max_data_requeues,
        receiver_secondary.blocked_credit_max_stream_data_requeues,
    );
    println!(
        "  接收端 PATH_ACK 同路/跨路：主路发送 {}/{}，备用路发送 {}/{}",
        receiver_primary.path_acks_same_path,
        receiver_primary.path_acks_cross_path,
        receiver_secondary.path_acks_same_path,
        receiver_secondary.path_acks_cross_path,
    );
    println!(
        "  ACK 逃生：发送端主路/备用路请求 {}/{}；接收端主路/备用路逃生 PATH_ACK {}/{}",
        after_primary.path_ack_escape_requests,
        after_secondary.path_ack_escape_requests,
        receiver_primary.path_ack_escape_acks,
        receiver_secondary.path_ack_escape_acks,
    );
    println!(
        "  故障时主路/备用路开放 {} / {}；首个主路 loss/PTO/恢复尝试/对冲 {}/{}/{}/{}，备用路首次 UDP {}",
        yes_or_no(observation.report.timeline.primary_open_at_fault),
        yes_or_no(observation.report.timeline.secondary_open_at_fault),
        optional_milliseconds(observation.report.timeline.first_primary_loss_timeout),
        optional_milliseconds(observation.report.timeline.first_primary_pto),
        optional_milliseconds(observation.report.timeline.first_primary_recovery_attempt),
        optional_milliseconds(observation.report.timeline.first_primary_hedge),
        optional_milliseconds(observation.report.timeline.first_secondary_udp_send),
    );
    println!(
        "  首个 ACK 进展超时/对冲 {}/{}",
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_primary_ack_progress_timeout,
        ),
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_primary_ack_progress_reinjection,
        ),
    );
    println!(
        "  备用路首个重传/新数据 {}/{}；首个从备用路代其他路径返回 PATH_ACK {}",
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_secondary_stream_retransmit,
        ),
        optional_milliseconds(observation.report.timeline.first_secondary_fresh_stream,),
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_receiver_secondary_cross_path_ack,
        ),
    );
    println!(
        "  最大断流窗口 {} → {}，恢复记录序号 {}；主路/备用路关闭时刻 {}/{}",
        optional_milliseconds(observation.report.recovery_gap_started_after_fault),
        optional_milliseconds(observation.report.recovery_gap_ended_after_fault),
        observation
            .report
            .recovery_gap_next_sequence
            .map_or_else(|| "无".to_owned(), |sequence| sequence.to_string()),
        optional_milliseconds(observation.report.timeline.primary_closed),
        optional_milliseconds(observation.report.timeline.secondary_closed),
    );
    println!(
        "  故障时主路 RTT/PTO {}/{}，cwnd/在途字节/需确认在途包 {}/{}/{}，包表总数/需确认包 {}/{}，PTO 计数 {}，定时器已武装 {}",
        milliseconds(observation.report.timeline.primary_rtt_at_fault),
        milliseconds(observation.report.timeline.primary_pto_at_fault),
        observation.report.timeline.primary_cwnd_at_fault,
        observation.report.timeline.primary_bytes_in_flight_at_fault,
        observation
            .report
            .timeline
            .primary_ack_eliciting_packets_in_flight_at_fault,
        observation
            .report
            .timeline
            .primary_tracked_sent_packets_at_fault,
        observation
            .report
            .timeline
            .primary_tracked_ack_eliciting_packets_at_fault,
        observation.report.timeline.primary_pto_count_at_fault,
        yes_or_no(
            observation
                .report
                .timeline
                .primary_loss_detection_timer_armed_at_fault,
        ),
    );
    println!(
        "  黑洞后主路需确认包号推进 {}；首个/末个需确认包 {}/{}，首个/末个入站 UDP {}/{}，定时器首次未武装 {}",
        after_primary.ack_eliciting_packet_number_advance,
        optional_milliseconds(observation.report.timeline.first_primary_ack_eliciting_send,),
        optional_milliseconds(observation.report.timeline.last_primary_ack_eliciting_send,),
        optional_milliseconds(observation.report.timeline.first_primary_udp_receive),
        optional_milliseconds(observation.report.timeline.last_primary_udp_receive),
        optional_milliseconds(observation.report.timeline.first_primary_loss_timer_unarmed,),
    );
    println!(
        "  主路最大在途字节/需确认在途包/包表总数/包表需确认包 {}/{}/{}/{}；首次归零 {}/{}",
        observation.report.timeline.max_primary_bytes_in_flight,
        observation
            .report
            .timeline
            .max_primary_ack_eliciting_packets_in_flight,
        observation.report.timeline.max_primary_tracked_sent_packets,
        observation
            .report
            .timeline
            .max_primary_tracked_ack_eliciting_packets,
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_primary_ack_eliciting_in_flight_zero,
        ),
        optional_milliseconds(
            observation
                .report
                .timeline
                .first_primary_tracked_ack_eliciting_zero,
        ),
    );
    println!(
        "  结束时主路/备用路仍开放 {} / {}{}",
        yes_or_no(observation.report.primary_path_open),
        yes_or_no(observation.report.secondary_path_open),
        observation
            .report
            .failure_reason
            .as_deref()
            .map(|reason| format!("；失败原因：{reason}"))
            .unwrap_or_default(),
    );
}

fn print_formal_failover_summary(observations: &[FormalFailoverObservation]) {
    println!();
    println!("正式 A 组汇总：");

    let mut all_directions_pass = true;
    for direction in FailoverDirection::ALL {
        let candidates: Vec<_> = observations
            .iter()
            .filter(|observation| {
                observation.direction == direction
                    && observation.pto_recovery == FORMAL_FAILOVER_CANDIDATE
            })
            .collect();
        let intact = candidates
            .iter()
            .filter(|observation| observation.report.data_intact)
            .count();
        let recovered = candidates
            .iter()
            .filter(|observation| observation.report.recovered)
            .count();
        let exchange_complete = candidates
            .iter()
            .filter(|observation| observation.report.exchange_complete)
            .count();
        let primary_used = candidates
            .iter()
            .filter(|observation| {
                observation
                    .report
                    .sender_primary_before_blackhole
                    .fresh_stream_bytes_sent
                    > 0
            })
            .count();
        let gaps: Vec<_> = candidates
            .iter()
            .filter_map(|observation| observation.report.recovery_gap)
            .map(milliseconds)
            .collect();
        let gap_summary = (!gaps.is_empty()).then(|| NumericSummary::from_samples(gaps));
        let pass = candidates.len() == SEED_PAIRS.len()
            && intact == SEED_PAIRS.len()
            && exchange_complete == SEED_PAIRS.len()
            && recovered == SEED_PAIRS.len()
            && primary_used == SEED_PAIRS.len()
            && gap_summary
                .as_ref()
                .is_some_and(|summary| summary.p95 < 1_000.0);
        all_directions_pass &= pass;

        let udp_ratios: Vec<_> = candidates
            .iter()
            .map(|candidate| {
                formal_failover_udp_bytes(&candidate.report) as f64
                    / formal_failover_udp_bytes(
                        &matching_formal_failover_baseline(
                            observations,
                            direction,
                            candidate.round,
                        )
                        .report,
                    ) as f64
                    * 100.0
            })
            .collect();
        let udp_summary = NumericSummary::from_samples(udp_ratios);

        println!(
            "- {}：数据完整 {intact}/{total}，最终响应闭环 {exchange_complete}/{total}，恢复 {recovered}/{total}，黑洞前主路承载数据 {primary_used}/{total}，P95 {}，黑洞后 UDP 相对基线中位 {:.2}%，门槛 {}",
            direction.description(),
            gap_summary
                .as_ref()
                .map(|summary| format!("{:.2} ms", summary.p95))
                .unwrap_or_else(|| "无有效样本".to_owned()),
            udp_summary.median,
            yes_or_no(pass),
            total = SEED_PAIRS.len(),
        );
    }

    println!(
        "- 正反两个方向是否都通过正式 A 组阶段门槛：{}",
        yes_or_no(all_directions_pass),
    );
}

fn print_candidate_only_formal_failover_summary(
    observations: &[FormalFailoverObservation],
    candidate: PtoRecovery,
    expected_per_direction: usize,
) {
    println!();
    println!("候选正式双向矩阵汇总：");

    let mut all_directions_pass = true;
    for direction in FailoverDirection::ALL {
        let candidates: Vec<_> = observations
            .iter()
            .filter(|observation| {
                observation.direction == direction && observation.pto_recovery == candidate
            })
            .collect();
        let intact = candidates
            .iter()
            .filter(|observation| observation.report.data_intact)
            .count();
        let exchange_complete = candidates
            .iter()
            .filter(|observation| observation.report.exchange_complete)
            .count();
        let recovered = candidates
            .iter()
            .filter(|observation| observation.report.recovered)
            .count();
        let primary_used = candidates
            .iter()
            .filter(|observation| {
                observation
                    .report
                    .sender_primary_before_blackhole
                    .fresh_stream_bytes_sent
                    > 0
            })
            .count();
        let gaps: Vec<_> = candidates
            .iter()
            .filter_map(|observation| observation.report.recovery_gap)
            .map(milliseconds)
            .collect();
        let strict_under_one_second = gaps.iter().filter(|&&gap| gap < 1_000.0).count();
        let gap_summary = (!gaps.is_empty()).then(|| NumericSummary::from_samples(gaps));
        let rescue_rounds = candidates
            .iter()
            .filter(|observation| {
                observation
                    .report
                    .sender_primary_after_blackhole
                    .stream_gap_rescue_probes
                    .saturating_add(
                        observation
                            .report
                            .sender_secondary_after_blackhole
                            .stream_gap_rescue_probes,
                    )
                    > 0
            })
            .count();
        let rescue_probes: u64 = candidates
            .iter()
            .map(|observation| {
                observation
                    .report
                    .sender_primary_after_blackhole
                    .stream_gap_rescue_probes
                    .saturating_add(
                        observation
                            .report
                            .sender_secondary_after_blackhole
                            .stream_gap_rescue_probes,
                    )
            })
            .sum();
        let rescue_bytes: u64 = candidates
            .iter()
            .map(|observation| {
                observation
                    .report
                    .sender_primary_after_blackhole
                    .stream_gap_rescue_bytes
                    .saturating_add(
                        observation
                            .report
                            .sender_secondary_after_blackhole
                            .stream_gap_rescue_bytes,
                    )
            })
            .sum();
        let pass = candidates.len() == expected_per_direction
            && intact == expected_per_direction
            && exchange_complete == expected_per_direction
            && recovered == expected_per_direction
            && primary_used == expected_per_direction
            && strict_under_one_second == expected_per_direction;
        all_directions_pass &= pass;

        println!(
            "- {}：数据完整 {intact}/{expected_per_direction}，最终响应闭环 {exchange_complete}/{expected_per_direction}，恢复 {recovered}/{expected_per_direction}，黑洞前主路承载数据 {primary_used}/{expected_per_direction}，严格 <1000 ms {strict_under_one_second}/{expected_per_direction}，中位 {}，P95/最差 {}，gap-watch 触发 {rescue_rounds} 场 / {rescue_probes} 包 / {rescue_bytes} 字节，门槛 {}",
            direction.description(),
            gap_summary
                .as_ref()
                .map(|summary| format!("{:.2} ms", summary.median))
                .unwrap_or_else(|| "无有效样本".to_owned()),
            gap_summary
                .as_ref()
                .map(|summary| format!("{:.2} / {:.2} ms", summary.p95, summary.maximum))
                .unwrap_or_else(|| "无有效样本".to_owned()),
            yes_or_no(pass),
        );
    }

    println!(
        "- 正反两个方向是否都满足逐场严格门槛：{}",
        yes_or_no(all_directions_pass),
    );
    print_failover_persistence_profile(observations, candidate);
}

fn strict_failover_violation(observation: &FormalFailoverObservation) -> bool {
    !observation.report.data_intact
        || !observation.report.exchange_complete
        || !observation.report.recovered
        || observation
            .report
            .recovery_gap
            .is_none_or(|gap| gap >= Duration::from_millis(1_000))
}

fn stable_multi_flight_has_reverse_recovery(observation: &FormalFailoverObservation) -> bool {
    let secondary = &observation.report.sender_secondary_after_blackhole;
    secondary.ack_progress_recovery_timeouts != 0
        || secondary.ack_progress_recovery_attempts != 0
        || secondary.ack_progress_recovery_empty_attempts != 0
        || secondary.ack_progress_reinjections != 0
        || secondary.ack_progress_reinjected_bytes != 0
        || secondary.ack_progress_feedback_probe_timeouts != 0
        || secondary.ack_progress_feedback_probes != 0
        || secondary.ack_progress_feedback_probe_bytes != 0
}

/// Stability-gated variants are allowed to advance only when every requested sample satisfies the
/// full failover gate and the healthy secondary never acts as the suspected ACK-progress source.
/// Run the complete requested batch before returning an error so failing evidence remains
/// preserved on disk.
fn verify_stable_multi_flight_gate(
    observations: &[FormalFailoverObservation],
    candidate: PtoRecovery,
    expected_samples: usize,
) -> LabResult<()> {
    if !matches!(
        candidate,
        PtoRecovery::CrossPathRecoveryWithStableMultiFlightBudget
            | PtoRecovery::CrossPathRecoveryWithDeliveryGapWatch
            | PtoRecovery::CrossPathRecoveryWithAlternativeStability
            | PtoRecovery::CrossPathRecoveryWithStreamProgressSnapshot
    ) {
        return Ok(());
    }

    let violations = observations
        .iter()
        .filter(|observation| {
            strict_failover_violation(observation)
                || observation
                    .report
                    .sender_primary_before_blackhole
                    .fresh_stream_bytes_sent
                    == 0
                || stable_multi_flight_has_reverse_recovery(observation)
        })
        .map(|observation| {
            let secondary = &observation.report.sender_secondary_after_blackhole;
            format!(
                "{}第{}轮(strict={}, secondary_timeout={}, secondary_attempt={}, secondary_probe={}, secondary_reinject={}, secondary_bytes={})",
                observation.direction.description(),
                observation.round,
                strict_failover_violation(observation),
                secondary.ack_progress_recovery_timeouts,
                secondary.ack_progress_recovery_attempts,
                secondary.ack_progress_feedback_probes,
                secondary.ack_progress_reinjections,
                secondary.ack_progress_reinjected_bytes,
            )
        })
        .collect::<Vec<_>>();

    if observations.len() != expected_samples || !violations.is_empty() {
        return Err(lab_error(format!(
            "稳定方向审计批次门槛失败：保留 {}/{} 个样本；违规项：{}",
            observations.len(),
            expected_samples,
            if violations.is_empty() {
                "无逐场违规，但样本数量不完整".to_owned()
            } else {
                violations.join("；")
            }
        )));
    }

    Ok(())
}

fn consecutive_violation_rate(violations: &[bool], window: usize) -> (usize, usize) {
    if window == 0 || window > violations.len() {
        return (0, 0);
    }
    let total = violations.len() - window + 1;
    let violated = violations
        .windows(window)
        .filter(|slice| slice.iter().all(|value| *value))
        .count();
    (violated, total)
}

fn maximum_consecutive_violations(violations: &[bool]) -> usize {
    violations
        .iter()
        .fold((0usize, 0usize), |(maximum, current), violated| {
            let current = if *violated { current + 1 } else { 0 };
            (maximum.max(current), current)
        })
        .0
}

fn print_failover_persistence_profile(
    observations: &[FormalFailoverObservation],
    candidate: PtoRecovery,
) {
    println!("连续严格违约画像（C-AVR，补充指标，不替代逐场全通过门槛）：");
    for direction in FailoverDirection::ALL {
        let mut candidates = observations
            .iter()
            .filter(|observation| {
                observation.direction == direction && observation.pto_recovery == candidate
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        candidates.sort_by_key(|observation| observation.round);
        let violations = candidates
            .into_iter()
            .map(strict_failover_violation)
            .collect::<Vec<_>>();
        let profile = (1..=violations.len().min(5))
            .map(|window| {
                let (violated, total) = consecutive_violation_rate(&violations, window);
                format!(
                    "k={window}: {violated}/{total} ({:.4})",
                    violated as f64 / total as f64
                )
            })
            .collect::<Vec<_>>()
            .join("，");
        println!(
            "- {}：最大连续违约 {} 场；{profile}",
            direction.description(),
            maximum_consecutive_violations(&violations),
        );
    }
}

fn formal_failover_udp_bytes(report: &SustainedFailoverReport) -> u64 {
    report
        .sender_primary_after_blackhole
        .udp_bytes_sent
        .saturating_add(report.sender_secondary_after_blackhole.udp_bytes_sent)
}

fn matching_formal_failover_baseline(
    observations: &[FormalFailoverObservation],
    direction: FailoverDirection,
    round: usize,
) -> &FormalFailoverObservation {
    observations
        .iter()
        .find(|observation| {
            observation.direction == direction
                && observation.round == round
                && observation.pto_recovery == PtoRecovery::Disabled
        })
        .expect("each completed formal failover round must contain the NoQ baseline")
}

fn matching_recovery_baseline(
    observations: &[RecoveryScreeningObservation],
    round: usize,
) -> &RecoveryScreeningObservation {
    observations
        .iter()
        .find(|observation| {
            observation.round == round && observation.pto_recovery == PtoRecovery::Disabled
        })
        .expect("each completed recovery round must contain the NoQ baseline")
}

fn total_pto_hedges(report: &NetworkBenchmarkReport) -> u64 {
    report
        .line_one
        .pto_hedges
        .saturating_add(report.line_two.pto_hedges)
}

fn total_pto_hedge_bytes(report: &NetworkBenchmarkReport) -> u64 {
    report
        .line_one
        .pto_hedge_bytes
        .saturating_add(report.line_two.pto_hedge_bytes)
}

#[test]
fn incomplete_round_does_not_invent_single_path_baseline() {
    assert!(
        try_best_single_throughput(&[], AggregationScenario::Balanced, 1).is_none(),
        "逐场保存时，尚未跑完的单路基线必须明确保持为空"
    );
}

#[test]
fn incomplete_continuous_round_cannot_pass_formal_gate() {
    assert!(
        try_b_continuous_best_single_throughput(&[], AggregationScenario::Balanced, 1).is_none(),
        "持续单流逐项落盘时，不完整轮次不能构造最佳单路"
    );
    assert!(!b_continuous_round_pass(
        &[],
        AggregationScenario::Balanced,
        1,
    ));
    assert!(!b_continuous_scenario_pass(
        &[],
        AggregationScenario::Balanced,
    ));
    assert!(!b_continuous_stage_pass(&[]));
}

#[test]
fn consecutive_violation_profile_distinguishes_persistent_tail_failures() {
    let violations = [false, true, true, false, true];
    assert_eq!(consecutive_violation_rate(&violations, 1), (3, 5));
    assert_eq!(consecutive_violation_rate(&violations, 2), (1, 4));
    assert_eq!(consecutive_violation_rate(&violations, 3), (0, 3));
    assert_eq!(maximum_consecutive_violations(&violations), 2);
}

async fn benchmark_multipath_candidates(
    line_one: LinkProfile,
    line_two: LinkProfile,
    transfer_size: usize,
    datagram_count: usize,
) -> LabResult<Vec<NetworkBenchmarkReport>> {
    let mut reports = Vec::with_capacity(MultipathScheduler::CANDIDATES.len());
    for scheduler in MultipathScheduler::CANDIDATES {
        apply_profiles(line_one, line_two, SEED_PAIRS[0])?;
        reports.push(
            run_network_benchmark(NetworkBenchmarkConfig::new(
                PathMode::MultipathAvailable,
                scheduler,
                transfer_size,
                datagram_count,
            ))
            .await?,
        );
    }
    Ok(reports)
}

async fn benchmark_recovery_candidates(
    line_one: LinkProfile,
    line_two: LinkProfile,
    transfer_size: usize,
    datagram_count: usize,
) -> LabResult<Vec<NetworkBenchmarkReport>> {
    let mut reports = Vec::with_capacity(PtoRecovery::CANDIDATES.len());
    for pto_recovery in PtoRecovery::CANDIDATES {
        apply_profiles(line_one, line_two, SEED_PAIRS[0])?;
        reports.push(
            run_network_benchmark(
                NetworkBenchmarkConfig::new(
                    PathMode::MultipathAvailable,
                    MultipathScheduler::NoqDefault,
                    transfer_size,
                    datagram_count,
                )
                .with_pto_recovery(pto_recovery),
            )
            .await?,
        );
    }
    Ok(reports)
}

fn ensure_isolated_network_namespace() -> LabResult<()> {
    if env::var("FLOWWEAVE_NETEM_LAB").as_deref() != Ok("1") {
        return Err(lab_error(
            "拒绝运行：缺少隔离实验标记，请使用 scripts/run_netem_lab.sh",
        ));
    }

    let parent_namespace = env::var("FLOWWEAVE_PARENT_NETNS")
        .map_err(|_| lab_error("拒绝运行：缺少原网络命名空间编号"))?;
    let current_namespace = fs::read_link("/proc/self/ns/net")?;
    if current_namespace.to_string_lossy() == parent_namespace {
        return Err(lab_error(
            "拒绝运行：当前进程仍在主网络命名空间，不能修改真实网络队列",
        ));
    }

    let uid_map = fs::read_to_string("/proc/self/uid_map")?;
    let mapped_as_root = uid_map
        .lines()
        .next()
        .is_some_and(|line| line.split_whitespace().next() == Some("0"));
    if !mapped_as_root {
        return Err(lab_error("拒绝运行：当前不是 rootless 映射的实验环境"));
    }
    Ok(())
}

fn ensure_benchmark_paths_absent(paths: &[&str]) -> LabResult<()> {
    for path in paths {
        if std::path::Path::new(path).exists() {
            return Err(lab_error(format!(
                "拒绝覆盖已有基准证据：{path}；请为新一轮实验注册新的文件名"
            )));
        }
    }
    Ok(())
}

fn apply_profiles(
    line_one: LinkProfile,
    line_two: LinkProfile,
    seeds: NetemSeeds,
) -> LabResult<()> {
    replace_line_profile("1:1", "10:", line_one, seeds.line_one)?;
    replace_line_profile("1:2", "20:", line_two, seeds.line_two)
}

fn replace_line_profile(
    parent: &'static str,
    handle: &'static str,
    profile: LinkProfile,
    seed: u32,
) -> LabResult<()> {
    let seed = seed.to_string();
    run_tc(&[
        "qdisc",
        "replace",
        "dev",
        "lo",
        "parent",
        parent,
        "handle",
        handle,
        "netem",
        "limit",
        "10000",
        "delay",
        profile.delay,
        "loss",
        profile.loss,
        "seed",
        &seed,
        "rate",
        profile.rate,
    ])
}

fn run_tc(arguments: &[&str]) -> LabResult<()> {
    let output = Command::new("tc").args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(lab_error(format!(
        "tc 命令失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn print_tc_statistics() -> LabResult<()> {
    let output = Command::new("tc")
        .args(["-s", "qdisc", "show", "dev", "lo"])
        .output()?;
    if !output.status.success() {
        return Err(lab_error(format!(
            "无法读取网络模拟统计：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    println!();
    println!("内核网络模拟器统计：");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn print_benchmark(report: &NetworkBenchmarkReport) {
    println!();
    println!("- 模式：{}", report.mode.description());
    println!(
        "  调度：{}",
        if report.mode == PathMode::MultipathAvailable {
            report.scheduler.description()
        } else {
            "单路径，不参与调度比较"
        }
    );
    println!("  PTO 恢复：{}", report.pto_recovery.description());
    println!(
        "  流传输：{} 字节，耗时 {:.2} ms，吞吐量 {:.2} Mbit/s",
        report.transfer_size,
        milliseconds(report.transfer_duration),
        report.throughput_mbps
    );
    print_datagrams(&report.datagrams);
    println!(
        "  线路一：首次流数据 {} 字节，重传流数据 {} 字节，UDP 总发送 {} 字节，丢失 {} 包，对冲 {} 次 / {} 字节，最终 RTT {:.2} ms",
        report.line_one.fresh_stream_bytes_sent,
        report.line_one.retransmitted_stream_bytes_sent,
        report.line_one.udp_bytes_sent,
        report.line_one.lost_packets,
        report.line_one.pto_hedges,
        report.line_one.pto_hedge_bytes,
        milliseconds(report.line_one.final_rtt)
    );
    println!(
        "  线路二：首次流数据 {} 字节，重传流数据 {} 字节，UDP 总发送 {} 字节，丢失 {} 包，对冲 {} 次 / {} 字节，最终 RTT {:.2} ms",
        report.line_two.fresh_stream_bytes_sent,
        report.line_two.retransmitted_stream_bytes_sent,
        report.line_two.udp_bytes_sent,
        report.line_two.lost_packets,
        report.line_two.pto_hedges,
        report.line_two.pto_hedge_bytes,
        milliseconds(report.line_two.final_rtt)
    );
    println!(
        "  QUIC UDP 总发送 {} 字节，其中应用数据之外约 {} 字节",
        report.total_udp_bytes_sent, report.extra_udp_bytes_sent
    );
    println!(
        "  稳定期资源：CPU {:.1}%（累计 {:.2} 秒），峰值常驻内存 {:.1} MiB",
        report.cpu_utilization_percent,
        report.cpu_time.as_secs_f64(),
        report.peak_rss_kib as f64 / 1024.0,
    );
    if report.mode == PathMode::MultipathAvailable {
        println!(
            "  实验结束时至少一条 / 全部已配置路径仍开放：{} / {}",
            yes_or_no(report.any_configured_path_open),
            yes_or_no(report.all_configured_paths_open)
        );
        println!(
            "  两条线路都承载至少 10% 首次应用数据：{}",
            yes_or_no(report.both_paths_carried_minimum_effective_share())
        );
    }
}

fn print_datagrams(datagrams: &DatagramMeasurement) {
    if datagrams.sent == 0 {
        println!("  Datagram：本场景不测");
        return;
    }

    println!(
        "  Datagram：发送 {}，收到 {}，应用层丢失 {:.2}%",
        datagrams.sent,
        datagrams.echoed,
        datagrams.loss_percent()
    );
    println!(
        "  Datagram 延迟：P50 {}，P95 {}，P99 {}",
        optional_milliseconds(datagrams.p50),
        optional_milliseconds(datagrams.p95),
        optional_milliseconds(datagrams.p99)
    );
}

fn print_realtime_report(report: &RealtimeDatagramReport) {
    println!(
        "  逻辑消息：{}；有效 {}，迟到 {}，丢失 {}，重复副本消息 {}，错误消息 {}",
        report.logical_messages,
        report.valid_messages,
        report.late_messages,
        report.lost_messages,
        report.duplicate_messages,
        report.error_messages
    );
    println!(
        "  有效到达率 {:.3}%；P50 {}，P95 {}，P99 {}",
        report.effective_arrival_percent(),
        optional_milliseconds(report.p50),
        optional_milliseconds(report.p95),
        optional_milliseconds(report.p99)
    );
    println!(
        "  副本 Datagram：排队 {}，接收观察 {}，结构正确 {}；主路/备用路 DATAGRAM 帧 {}/{}（每路预期 {}）",
        report.queued_copy_datagrams,
        report.observed_copy_datagrams,
        report.decoded_copy_datagrams,
        report.line_one_datagram_frames_sent,
        report.line_two_datagram_frames_sent,
        report.batches
    );
    println!(
        "  UDP 字节：主路 {}，备用路 {}，合计 {}；逻辑应用字节 {}，比率 {:.4}×",
        report.line_one_udp_bytes_sent,
        report.line_two_udp_bytes_sent,
        report.total_udp_bytes_sent,
        report.logical_application_bytes,
        report.udp_wire_ratio()
    );
    println!(
        "  错误细分：畸形副本 {}，批次 {}，序号 {}，时间戳 {}，摘要 {}，内容 {}",
        report.malformed_copy_datagrams,
        report.invalid_batch_messages,
        report.invalid_sequence_messages,
        report.timestamp_error_messages,
        report.digest_error_messages,
        report.content_error_messages
    );
    println!(
        "  两路径副本精确落位：{}；测量闭合：{}；路径仍开放：{}/{}；烟测安全门槛：{}；正式绝对门槛：{}",
        yes_or_no(report.copies_used_distinct_paths()),
        yes_or_no(report.measurement_is_complete()),
        yes_or_no(report.primary_path_open),
        yes_or_no(report.secondary_path_open),
        yes_or_no(report.smoke_safety_pass()),
        yes_or_no(report.stage_pass())
    );
}

fn print_realtime_v3_wire_report(report: &RealtimeV3WireReport) {
    println!();
    println!(
        "- v3 门控：逻辑消息 {}，编码块 {}；原件/成对校验/全局校验排队 {}/{}/{}",
        report.logical_messages,
        report.blocks,
        report.queued_original_frames,
        report.queued_pair_parity_frames,
        report.queued_global_parity_frames
    );
    println!(
        "  主路正确原件延迟：P50 {}，P95 {}，P99 {}；原件/成对校验/全局 0/全局 1 接收 {}/{}/{}/{}",
        optional_milliseconds(report.original_p50),
        optional_milliseconds(report.original_p95),
        optional_milliseconds(report.original_p99),
        report.observed_original_frames,
        report.observed_pair_parity_frames,
        report.observed_global_zero_frames,
        report.observed_global_one_frames
    );
    println!(
        "  UDP 字节：主路 {}，备用路 {}，合计 {}；逻辑应用字节 {}，比率 {:.6}×；UDP 包 {}/{}",
        report.line_one_udp_bytes_sent,
        report.line_two_udp_bytes_sent,
        report.total_udp_bytes_sent,
        report.logical_application_bytes,
        report.udp_wire_ratio(),
        report.line_one_udp_datagrams_sent,
        report.line_two_udp_datagrams_sent
    );
    println!(
        "  DATAGRAM 帧：主路 {}，备用路 {}；独立构包确认 {}/{}；错误 {}（畸形 {}、头 {}、摘要 {}、内容 {}、时间 {}）",
        report.line_one_datagram_frames_sent,
        report.line_two_datagram_frames_sent,
        report.isolation_confirmations,
        report.queued_frames(),
        report.error_frames(),
        report.malformed_frames,
        report.invalid_header_frames,
        report.digest_error_frames,
        report.content_error_frames,
        report.timestamp_error_frames
    );
    println!(
        "  精确落位：{}；独立构包：{}；测量闭合：{}；路径仍开放：{}/{}；线速/延迟门控：{}",
        yes_or_no(report.frames_exactly_routed()),
        yes_or_no(report.frames_isolated()),
        yes_or_no(report.measurement_is_complete()),
        yes_or_no(report.primary_path_open),
        yes_or_no(report.secondary_path_open),
        yes_or_no(report.wire_latency_gate_pass())
    );
}

fn print_realtime_controller_gate_report(report: &RealtimeControllerGateReport) {
    println!(
        "- {}：有效 {}，迟到 {}，丢失 {}，错误 {}；P50 {}，P95 {}，P99 {}",
        report.congestion.description(),
        report.valid_messages,
        report.late_messages,
        report.lost_messages,
        report.error_frames(),
        optional_milliseconds(report.p50),
        optional_milliseconds(report.p95),
        optional_milliseconds(report.p99)
    );
    println!(
        "  UDP：主路 {} 字节 / {} 包，备用路 {} 字节 / {} 包，总比率 {:.6}×；DATAGRAM 帧 {}/{}",
        report.line_one_udp_bytes_sent,
        report.line_one_udp_datagrams_sent,
        report.line_two_udp_bytes_sent,
        report.line_two_udp_datagrams_sent,
        report.udp_wire_ratio(),
        report.line_one_datagram_frames_sent,
        report.line_two_datagram_frames_sent
    );
    println!(
        "  排队/观察/解码 {}/{}/{}；CPU {:.3}%，RSS {} KiB；精确落位 {}，测量闭合 {}，路径开放 {}/{}，可行性门控 {}",
        report.queued_frames,
        report.observed_frames,
        report.decoded_frames,
        report.cpu_utilization_percent,
        report.peak_rss_kib,
        yes_or_no(report.frames_exactly_routed()),
        yes_or_no(report.measurement_is_complete()),
        yes_or_no(report.primary_path_open),
        yes_or_no(report.secondary_path_open),
        yes_or_no(report.feasibility_gate_pass())
    );
}

fn print_realtime_v4_report(report: &RealtimeV4Report) {
    println!(
        "- v4：有效 {}/{}（{:.3}%），迟到 {}，丢失 {}，重复 {}，错误 {}",
        report.valid_messages,
        report.logical_messages,
        report.effective_arrival_percent(),
        report.late_messages,
        report.lost_messages,
        report.duplicate_messages,
        report.error_messages()
    );
    println!(
        "  延迟：P50 {}，P95 {}，P99 {}；交付来源 原件/成对/全局 {}/{}/{}",
        optional_milliseconds(report.p50),
        optional_milliseconds(report.p95),
        optional_milliseconds(report.p99),
        report.original_deliveries,
        report.pair_recoveries,
        report.global_recoveries
    );
    println!(
        "  观察帧：原件/成对/全局 0/全局 1 {}/{}/{}/{}；排队原件/成对/全局 {}/{}/{}",
        report.observed_original_frames,
        report.observed_pair_parity_frames,
        report.observed_global_zero_frames,
        report.observed_global_one_frames,
        report.queued_original_frames,
        report.queued_pair_parity_frames,
        report.queued_global_parity_frames
    );
    println!(
        "  UDP：主路 {} 字节 / {} 包，备用路 {} 字节 / {} 包，总比率 {:.6}×；DATAGRAM 帧 {}/{}",
        report.line_one_udp_bytes_sent,
        report.line_one_udp_datagrams_sent,
        report.line_two_udp_bytes_sent,
        report.line_two_udp_datagrams_sent,
        report.udp_wire_ratio(),
        report.line_one_datagram_frames_sent,
        report.line_two_datagram_frames_sent
    );
    println!(
        "  CPU {:.3}%，RSS {} KiB；精确落位 {}，独立包边界 {}，测量闭合 {}，路径开放 {}/{}，安全门槛 {}，完整门槛 {}",
        report.cpu_utilization_percent,
        report.peak_rss_kib,
        yes_or_no(report.frames_exactly_routed()),
        yes_or_no(report.application_frames_are_separate()),
        yes_or_no(report.measurement_is_complete()),
        yes_or_no(report.primary_path_open),
        yes_or_no(report.secondary_path_open),
        yes_or_no(report.safety_pass()),
        yes_or_no(report.stage_pass())
    );
}

fn print_realtime_v12_report(report: &RealtimeV12Report) {
    println!(
        "- v12：有效 {}/{}（{:.3}%），迟到 {}，丢失 {}，重复分片帧 {}，错误 {}",
        report.valid_messages,
        report.logical_messages,
        report.effective_arrival_percent(),
        report.late_messages,
        report.lost_messages,
        report.duplicate_shard_frames,
        report.error_messages()
    );
    println!(
        "  延迟：P50 {}，P95 {}，P99 {}；首次交付 系统分片/本地 XOR/全局 {}/{}/{}",
        optional_milliseconds(report.p50),
        optional_milliseconds(report.p95),
        optional_milliseconds(report.p99),
        report.systematic_deliveries,
        report.local_xor_recoveries,
        report.global_recoveries
    );
    println!(
        "  观察帧：Data0/Data1/LocalParity/全局行 0/1/2 {}/{}/{}/{}/{}/{}；排队 Data0/Data1/LocalParity/全局 {}/{}/{}/{}",
        report.observed_data0_frames,
        report.observed_data1_frames,
        report.observed_local_parity_frames,
        report.observed_global_row_0_frames,
        report.observed_global_row_1_frames,
        report.observed_global_row_2_frames,
        report.queued_data0_frames,
        report.queued_data1_frames,
        report.queued_local_parity_frames,
        report.queued_global_parity_frames
    );
    println!(
        "  线协议：头 {} 字节，分片 {} 字节，固定帧 {} 字节",
        report.header_size_bytes, report.shard_size_bytes, report.frame_size_bytes
    );
    println!(
        "  UDP：主路 {} 字节 / {} 包，备用路 {} 字节 / {} 包，总比率 {:.6}×；DATAGRAM 帧 {}/{}",
        report.line_one_udp_bytes_sent,
        report.line_one_udp_datagrams_sent,
        report.line_two_udp_bytes_sent,
        report.line_two_udp_datagrams_sent,
        report.udp_wire_ratio(),
        report.line_one_datagram_frames_sent,
        report.line_two_datagram_frames_sent
    );
    println!(
        "  CPU {:.3}%，RSS {} KiB；精确落位 {}，独立包边界 {}，GSO 启用 {}，非零超块 accounting 测试 {}，2-of-3 accounting 测试 {}，测量闭合 {}，路径开放 {}/{}，安全门槛 {}，完整门槛 {}",
        report.cpu_utilization_percent,
        report.peak_rss_kib,
        yes_or_no(report.frames_exactly_routed()),
        yes_or_no(report.application_frames_are_separate()),
        yes_or_no(report.segmentation_offload_enabled),
        yes_or_no(report.nonzero_superblock_accounting_test),
        yes_or_no(report.two_of_three_accounting_test),
        yes_or_no(report.measurement_is_complete()),
        yes_or_no(report.primary_path_open),
        yes_or_no(report.secondary_path_open),
        yes_or_no(report.safety_pass()),
        yes_or_no(report.stage_pass())
    );
}

fn print_hysteria_realtime_report(report: &HysteriaRealtimeReport) {
    println!();
    println!(
        "- Hysteria {} / {}：有效 {}/{}（{:.3}%），迟到 {}，丢失 {}，重复 {}，错误 {}",
        report.congestion.description(),
        report.line.description(),
        report.valid_messages,
        report.logical_messages,
        report.effective_arrival_percent(),
        report.late_messages,
        report.lost_messages,
        report.duplicate_messages,
        report.error_messages()
    );
    println!(
        "  延迟：P50 {}，P95 {}，P99 {}；观察/解码 Datagram {}/{}",
        optional_milliseconds(report.p50),
        optional_milliseconds(report.p95),
        optional_milliseconds(report.p99),
        report.observed_datagrams,
        report.decoded_datagrams
    );
    println!(
        "  客户端 QUIC UDP 载荷：线路一 {} 字节 / {} 包，线路二 {} 字节 / {} 包；合计比率 {:.4}×",
        report.line_one_udp_payload_bytes,
        report.line_one_client_packets,
        report.line_two_udp_payload_bytes,
        report.line_two_client_packets,
        report.udp_wire_ratio()
    );
    println!(
        "  测量闭合：{}；只使用目标线路：{}；进程存活：{}；基础设施门槛：{}",
        yes_or_no(report.measurement_is_complete()),
        yes_or_no(report.used_only_target_line()),
        yes_or_no(report.processes_alive_at_end),
        yes_or_no(report.smoke_safety_pass())
    );
}

fn print_hysteria_c_summary(observations: &[HysteriaRealtimeObservation]) {
    println!();
    println!("Hysteria C 组逐参赛项汇总：");
    for congestion in HysteriaCongestion::ALL {
        for line in HysteriaLine::ALL {
            let matching = observations
                .iter()
                .filter(|observation| {
                    observation.report.congestion == congestion && observation.report.line == line
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                continue;
            }
            let p95 = matching
                .iter()
                .filter_map(|observation| observation.report.p95)
                .map(milliseconds)
                .collect::<Vec<_>>();
            let total_lost = matching
                .iter()
                .map(|observation| observation.report.lost_messages)
                .sum::<usize>();
            let arrival = NumericSummary::from_samples(
                matching
                    .iter()
                    .map(|observation| observation.report.effective_arrival_percent()),
            );
            let p95_summary = (!p95.is_empty()).then(|| NumericSummary::from_samples(p95));
            println!(
                "- {} / {}：有效到达率中位 {:.3}%，最小 {:.3}%；P95 中位 {}；{} 轮总丢失 {}",
                congestion.description(),
                line.description(),
                arrival.median,
                arrival.minimum,
                p95_summary
                    .map(|summary| format!("{:.3} ms", summary.median))
                    .unwrap_or_else(|| "无有效样本".to_owned()),
                matching.len(),
                total_lost
            );
        }
    }
}

fn print_hysteria_throughput_report(report: &HysteriaThroughputReport) {
    println!(
        "- Hysteria {} / {}：{:.3} Mbit/s，接收记录 {}，客户端 UDP {} 字节，服务端 UDP {} 字节，线速 {:.4}x，额外 {:.4}x，完整 {}，进程存活 {}，基础通过 {}",
        report.congestion.description(),
        report.line.description(),
        report.throughput_mbps,
        report.records_received_in_window,
        report.target_client_udp_payload_bytes(),
        report.target_server_udp_payload_bytes(),
        report.udp_wire_ratio(),
        report.extra_wire_ratio(),
        yes_or_no(report.data_intact && report.exchange_complete),
        yes_or_no(report.processes_alive_at_end),
        yes_or_no(report.infrastructure_pass()),
    );
}

fn hysteria_b_participant_summary(
    observations: &[HysteriaThroughputObservation],
    scenario: AggregationScenario,
    congestion: HysteriaCongestion,
    line: HysteriaLine,
) -> Option<(NumericSummary, NumericSummary, NumericSummary)> {
    let matching = observations
        .iter()
        .filter(|observation| {
            observation.scenario == scenario
                && observation.report.congestion == congestion
                && observation.report.line == line
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return None;
    }
    Some((
        NumericSummary::from_samples(
            matching
                .iter()
                .map(|observation| observation.report.throughput_mbps),
        ),
        NumericSummary::from_samples(
            matching
                .iter()
                .map(|observation| observation.report.udp_wire_ratio()),
        ),
        NumericSummary::from_samples(
            matching
                .iter()
                .map(|observation| observation.report.extra_wire_ratio()),
        ),
    ))
}

fn hysteria_b_best_participant(
    observations: &[HysteriaThroughputObservation],
    scenario: AggregationScenario,
) -> Option<(
    HysteriaCongestion,
    HysteriaLine,
    NumericSummary,
    NumericSummary,
    NumericSummary,
)> {
    HysteriaCongestion::ALL
        .into_iter()
        .flat_map(|congestion| {
            HysteriaLine::ALL
                .into_iter()
                .map(move |line| (congestion, line))
        })
        .filter_map(|(congestion, line)| {
            hysteria_b_participant_summary(observations, scenario, congestion, line)
                .map(|(throughput, wire, extra)| (congestion, line, throughput, wire, extra))
        })
        .max_by(|left, right| left.2.median.total_cmp(&right.2.median))
}

fn print_hysteria_b_summary(observations: &[HysteriaThroughputObservation]) {
    println!();
    println!("Hysteria B 组逐参赛项汇总：");
    for scenario in AggregationScenario::ALL {
        println!();
        println!("场景：{}", scenario.description());
        for congestion in HysteriaCongestion::ALL {
            for line in HysteriaLine::ALL {
                let Some((throughput, wire, extra)) =
                    hysteria_b_participant_summary(observations, scenario, congestion, line)
                else {
                    continue;
                };
                let rounds = observations
                    .iter()
                    .filter(|observation| {
                        observation.scenario == scenario
                            && observation.report.congestion == congestion
                            && observation.report.line == line
                    })
                    .count();
                println!(
                    "- {} / {}：{} 轮吞吐中位 {:.3}、最差 {:.3} Mbit/s；线速中位 {:.4}x，额外中位 {:.4}x",
                    congestion.description(),
                    line.description(),
                    rounds,
                    throughput.median,
                    throughput.worst,
                    wire.median,
                    extra.median,
                );
            }
        }

        if let Some((congestion, line, throughput, wire, extra)) =
            hysteria_b_best_participant(observations, scenario)
        {
            let flowweave = scenario.flowweave_throughput_median();
            let flowweave_wire = scenario.flowweave_wire_ratio_median();
            let flowweave_extra = (flowweave_wire - 1.0).max(0.0);
            let throughput_ratio = flowweave / throughput.median;
            let wire_pass = if extra.median > 0.0 {
                flowweave_extra <= extra.median * 2.0
            } else {
                flowweave_wire <= wire.median
            };
            println!(
                "  最强吞吐对手：{} / {} {:.3} Mbit/s；FlowWeave {:.3} Mbit/s，相对 {:.1}%，吞吐门槛 {}；FlowWeave/Hysteria 额外线速 {:.4}/{:.4}x，线速门槛 {}",
                congestion.description(),
                line.description(),
                throughput.median,
                flowweave,
                throughput_ratio * 100.0,
                yes_or_no(throughput_ratio >= 1.15),
                flowweave_extra,
                extra.median,
                yes_or_no(wire_pass),
            );
        }
    }
}

fn verify_hysteria_b_final_comparison(
    observations: &[HysteriaThroughputObservation],
) -> LabResult<()> {
    let expected = AggregationScenario::ALL.len()
        * HysteriaCongestion::ALL.len()
        * HysteriaLine::ALL.len()
        * SEED_PAIRS.len();
    if observations.len() != expected
        || observations
            .iter()
            .any(|item| !item.report.infrastructure_pass())
    {
        return Err(lab_error(format!(
            "Hysteria B 正式矩阵基础证据不完整：实际 {}/{} 项",
            observations.len(),
            expected,
        )));
    }

    let mut failed = Vec::new();
    for scenario in AggregationScenario::ALL {
        let Some((congestion, line, throughput, wire, extra)) =
            hysteria_b_best_participant(observations, scenario)
        else {
            failed.push(format!("{}缺少 Hysteria 汇总", scenario.description()));
            continue;
        };
        let strongest_count = observations
            .iter()
            .filter(|observation| {
                observation.scenario == scenario
                    && observation.report.congestion == congestion
                    && observation.report.line == line
            })
            .count();
        if strongest_count != SEED_PAIRS.len() {
            failed.push(format!("{}最强对手样本不完整", scenario.description()));
            continue;
        }
        let flowweave = scenario.flowweave_throughput_median();
        let flowweave_wire = scenario.flowweave_wire_ratio_median();
        let flowweave_extra = (flowweave_wire - 1.0).max(0.0);
        let throughput_pass = throughput.median > 0.0 && flowweave / throughput.median >= 1.15;
        let wire_pass = if extra.median > 0.0 {
            flowweave_extra <= extra.median * 2.0
        } else {
            flowweave_wire <= wire.median
        };
        if !throughput_pass || !wire_pass {
            failed.push(format!(
                "{}：对手 {} / {} {:.3} Mbit/s，FlowWeave {:.3}，额外线速 {:.4}/{:.4}x",
                scenario.description(),
                congestion.description(),
                line.description(),
                throughput.median,
                flowweave,
                flowweave_extra,
                extra.median,
            ));
        }
    }

    if failed.is_empty() {
        println!("FlowWeave B 在两个场景的吞吐和额外线速相对门槛均胜过 Hysteria 2.9.3。");
        return Ok(());
    }
    Err(lab_error(format!(
        "FlowWeave B 未通过 Hysteria 2.9.3 最终相对门槛：{}",
        failed.join("；"),
    )))
}

fn print_hysteria_failover_report(report: &HysteriaFailoverReport) {
    println!();
    println!(
        "- Hysteria {} / {}：原 TCP 连接复用 {}，故障后恢复 {}，数据完整 {}，最终响应闭合 {}，连续性通过 {}",
        report.congestion.description(),
        report.direction.description(),
        yes_or_no(report.original_connection_reused),
        yes_or_no(report.recovered_after_failure),
        yes_or_no(report.data_intact),
        yes_or_no(report.exchange_complete),
        yes_or_no(report.continuity_pass)
    );
    println!(
        "  正确记录：故障前 {}，故障后 {}，合计 {} / {} 字节；恢复最大间隔 {}",
        report.records_before_failure,
        report.records_after_failure,
        report.records_received,
        report.application_bytes_received,
        optional_milliseconds(report.recovery_gap)
    );
    println!(
        "  故障后客户端 UDP：线路一 {} 字节 / {} 包，线路二 {} 字节 / {} 包",
        report.client_line_one_udp_payload_bytes_after_failure,
        report.client_line_one_packets_after_failure,
        report.client_line_two_udp_payload_bytes_after_failure,
        report.client_line_two_packets_after_failure
    );
    println!(
        "  故障后服务端 UDP：线路一 {} 字节 / {} 包，线路二 {} 字节 / {} 包；进程存活 {}，基础设施门槛 {}",
        report.server_line_one_udp_payload_bytes_after_failure,
        report.server_line_one_packets_after_failure,
        report.server_line_two_udp_payload_bytes_after_failure,
        report.server_line_two_packets_after_failure,
        yes_or_no(report.processes_alive_at_end),
        yes_or_no(report.infrastructure_pass())
    );
    if let Some(reason) = &report.failure_reason {
        println!("  未通过原因：{reason}");
    }
}

fn print_hysteria_a_summary(observations: &[HysteriaFailoverObservation]) {
    println!();
    println!("Hysteria A 组逐方向、逐模式汇总：");
    for direction in FailoverDirection::ALL {
        for congestion in HysteriaCongestion::ALL {
            let matching = observations
                .iter()
                .filter(|observation| {
                    observation.direction == direction
                        && observation.report.congestion == congestion
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                continue;
            }
            let continuity = matching
                .iter()
                .filter(|observation| observation.report.continuity_pass)
                .count();
            let recovered = matching
                .iter()
                .filter(|observation| observation.report.recovered_after_failure)
                .count();
            let recovery_gaps = matching
                .iter()
                .filter_map(|observation| observation.report.recovery_gap)
                .map(milliseconds)
                .collect::<Vec<_>>();
            let recovery_summary =
                (!recovery_gaps.is_empty()).then(|| NumericSummary::from_samples(recovery_gaps));
            println!(
                "- {} / {}：连续性 {continuity}/{}，故障后有数据 {recovered}/{}，恢复间隔中位 {}，基础设施 {}/{}",
                direction.description(),
                congestion.description(),
                matching.len(),
                matching.len(),
                recovery_summary
                    .map(|summary| format!("{:.3} ms", summary.median))
                    .unwrap_or_else(|| "无恢复样本".to_owned()),
                matching
                    .iter()
                    .filter(|observation| observation.report.infrastructure_pass())
                    .count(),
                matching.len()
            );
        }
    }
}

fn print_failover(report: &FailoverReport) {
    println!();
    println!("- 调度：{}", report.scheduler.description());
    println!("- PTO 恢复：{}", report.pto_recovery.description());
    println!(
        "- 实验设置的单路径空闲判定上限：{:.0} ms",
        milliseconds(report.configured_path_idle_timeout)
    );
    println!("- 是否在原连接上恢复：{}", yes_or_no(report.recovered));
    match report.recovery_time {
        Some(duration) => println!(
            "- 从断路到首个有效载荷字节恢复：{:.2} ms",
            milliseconds(duration)
        ),
        None => println!(
            "- 未恢复原因：{}",
            report.failure_reason.as_deref().unwrap_or("原因未知")
        ),
    }
    if let Some(duration) = report.completion_time {
        println!(
            "- 从断路到完整校验 256 KiB：{:.2} ms",
            milliseconds(duration)
        );
    }
    println!(
        "- 断路后主线路发送 {} 字节、丢失 {} 包",
        report.primary_bytes_after_blackhole, report.primary_lost_packets
    );
    println!(
        "- 断路后备用线路发送 {} 字节、丢失 {} 包",
        report.secondary_bytes_after_blackhole, report.secondary_lost_packets
    );
    println!(
        "- 主路/备用路对冲：{} / {} 次，入队载荷 {} / {} 字节",
        report.primary_pto_hedges,
        report.secondary_pto_hedges,
        report.primary_pto_hedge_bytes,
        report.secondary_pto_hedge_bytes,
    );
    println!(
        "- 观察结束时主路/备用路仍开放：{} / {}",
        yes_or_no(report.primary_path_open),
        yes_or_no(report.secondary_path_open),
    );
}

fn print_comparison(
    name: &str,
    line_one: &NetworkBenchmarkReport,
    line_two: &NetworkBenchmarkReport,
    multipath: &NetworkBenchmarkReport,
) {
    let best_single = line_one.throughput_mbps.max(line_two.throughput_mbps);
    let ratio = if best_single > 0.0 {
        multipath.throughput_mbps / best_single
    } else {
        0.0
    };
    let conclusion = if ratio >= 1.10 {
        "本轮超过最佳单线路 10%，但必须结合多轮中位数才能判断"
    } else if ratio <= 0.95 {
        "本轮比最佳单线路至少慢 5%，不能把本轮结果称为聚合"
    } else {
        "本轮与最佳单线路接近，尚无明确聚合收益"
    };

    println!();
    println!(
        "{name}对照：最佳单线路 {:.2} Mbit/s，{} {:.2} Mbit/s（{:.1}%）",
        best_single,
        multipath.scheduler.description(),
        multipath.throughput_mbps,
        ratio * 100.0
    );
    println!("{name}判断：{conclusion}");
}

fn print_screening_observation(participant: ScreeningParticipant, report: &NetworkBenchmarkReport) {
    println!(
        "- {}：{:.2} Mbit/s；线路一/二首次数据 {} / {} 字节；重传 {} / {} 字节；最小有效占比 {:.1}%；线速 {:.2} 倍；CPU {:.1}%；峰值内存 {:.1} MiB",
        participant.description(),
        report.throughput_mbps,
        report.line_one.fresh_stream_bytes_sent,
        report.line_two.fresh_stream_bytes_sent,
        report.line_one.retransmitted_stream_bytes_sent,
        report.line_two.retransmitted_stream_bytes_sent,
        minimum_effective_share_percent(report),
        wire_ratio(report),
        report.cpu_utilization_percent,
        report.peak_rss_kib as f64 / 1024.0,
    );
}

fn print_screening_summary(observations: &[ScreeningObservation]) {
    println!();
    println!("五种子汇总（P95 对吞吐量是高端样本，最差值取最低吞吐量）：");

    for scenario in AggregationScenario::ALL {
        println!();
        println!("场景：{}", scenario.description());

        for participant in ScreeningParticipant::ALL {
            let matching: Vec<_> = observations
                .iter()
                .filter(|observation| {
                    observation.scenario == scenario && observation.participant == participant
                })
                .collect();
            let throughput = NumericSummary::from_samples(
                matching
                    .iter()
                    .map(|observation| observation.report.throughput_mbps),
            );
            println!(
                "- {}吞吐量：中位 {:.2}，P95 {:.2}，最差 {:.2}，范围 {:.2}～{:.2}，波动 {:.2} Mbit/s",
                participant.description(),
                throughput.median,
                throughput.p95,
                throughput.worst,
                throughput.minimum,
                throughput.maximum,
                throughput.range(),
            );
            let cpu = NumericSummary::from_samples(
                matching
                    .iter()
                    .map(|observation| observation.report.cpu_utilization_percent),
            );
            let memory = NumericSummary::from_samples(
                matching
                    .iter()
                    .map(|observation| observation.report.peak_rss_kib as f64 / 1024.0),
            );
            println!(
                "  资源：CPU 中位 {:.1}%、最差/最高 {:.1}%；峰值内存中位 {:.1} MiB、最差/最高 {:.1} MiB",
                cpu.median, cpu.maximum, memory.median, memory.maximum,
            );

            if !matches!(participant, ScreeningParticipant::Multipath(_)) {
                continue;
            }

            let improvements: Vec<_> = matching
                .iter()
                .map(|observation| {
                    observation.report.throughput_mbps
                        / best_single_throughput(observations, scenario, observation.round)
                })
                .collect();
            let improvement =
                NumericSummary::from_samples(improvements.iter().map(|ratio| ratio * 100.0));
            let faster_rounds = improvements.iter().filter(|ratio| **ratio >= 1.15).count();
            let minimum_shares: Vec<_> = matching
                .iter()
                .map(|observation| minimum_effective_share_percent(&observation.report))
                .collect();
            let share = NumericSummary::from_samples(minimum_shares.iter().copied());
            let share_passes = minimum_shares
                .iter()
                .filter(|share| **share >= 10.0)
                .count();
            let wire = NumericSummary::from_samples(
                matching
                    .iter()
                    .map(|observation| wire_ratio(&observation.report)),
            );

            println!(
                "  相对当轮最佳单路：中位 {:.1}%，P95 {:.1}%，最差 {:.1}%，4/5 门槛命中 {faster_rounds}/5",
                improvement.median, improvement.p95, improvement.worst,
            );
            println!(
                "  每轮较少线路的首次数据占比：中位 {:.1}%，最差 {:.1}%，10% 门槛命中 {share_passes}/5",
                share.median, share.worst,
            );
            println!(
                "  线速/应用数据：中位 {:.2} 倍，P95/最差 {:.2} 倍，范围 {:.2}～{:.2}",
                wire.median, wire.maximum, wire.minimum, wire.maximum,
            );
        }
    }
}

fn best_single_throughput(
    observations: &[ScreeningObservation],
    scenario: AggregationScenario,
    round: usize,
) -> f64 {
    try_best_single_throughput(observations, scenario, round)
        .expect("each completed round must contain both single-path baselines")
}

fn try_best_single_throughput(
    observations: &[ScreeningObservation],
    scenario: AggregationScenario,
    round: usize,
) -> Option<f64> {
    let line_one = observations
        .iter()
        .find(|observation| {
            observation.scenario == scenario
                && observation.round == round
                && observation.participant == ScreeningParticipant::LineOne
        })
        .map(|observation| observation.report.throughput_mbps);
    let line_two = observations
        .iter()
        .find(|observation| {
            observation.scenario == scenario
                && observation.round == round
                && observation.participant == ScreeningParticipant::LineTwo
        })
        .map(|observation| observation.report.throughput_mbps);

    Some(line_one?.max(line_two?))
}

fn minimum_effective_share_percent(report: &NetworkBenchmarkReport) -> f64 {
    let line_one = report.line_one.fresh_stream_bytes_sent;
    let line_two = report.line_two.fresh_stream_bytes_sent;
    let total = line_one.saturating_add(line_two);
    if total == 0 {
        return 0.0;
    }
    line_one.min(line_two) as f64 / total as f64 * 100.0
}

fn wire_ratio(report: &NetworkBenchmarkReport) -> f64 {
    if report.transfer_size == 0 {
        return 0.0;
    }
    report.total_udp_bytes_sent as f64 / report.transfer_size as f64
}

fn b_continuous_wire_ratio(report: &ContinuousBenchmarkReport) -> f64 {
    if report.transfer_size == 0 {
        return 0.0;
    }
    report.total_udp_bytes_sent as f64 / report.transfer_size as f64
}

fn b_continuous_minimum_share_percent(report: &ContinuousBenchmarkReport) -> f64 {
    let line_one = report.line_one.fresh_stream_bytes_sent;
    let line_two = report.line_two.fresh_stream_bytes_sent;
    let total = line_one.saturating_add(line_two);
    if total == 0 {
        return 0.0;
    }
    line_one.min(line_two) as f64 / total as f64 * 100.0
}

fn find_b_continuous_observation(
    observations: &[BContinuousObservation],
    scenario: AggregationScenario,
    round: usize,
    participant: BContinuousParticipant,
) -> Option<&BContinuousObservation> {
    observations.iter().find(|observation| {
        observation.scenario == scenario
            && observation.round == round
            && observation.participant == participant
    })
}

fn b_continuous_participant_pass(observation: &BContinuousObservation) -> bool {
    let report = &observation.report;
    let mode_paths_pass = match observation.participant {
        BContinuousParticipant::LineOne => {
            report.line_one.fresh_stream_bytes_sent > 0
                && report.line_two.fresh_stream_bytes_sent == 0
        }
        BContinuousParticipant::LineTwo => {
            report.line_one.fresh_stream_bytes_sent == 0
                && report.line_two.fresh_stream_bytes_sent > 0
        }
        BContinuousParticipant::Multipath => {
            report.line_one.fresh_stream_bytes_sent > 0
                && report.line_two.fresh_stream_bytes_sent > 0
        }
    };
    let transfer_matches_records = u64::try_from(report.transfer_size).is_ok_and(|transfer_size| {
        report
            .records_received_in_window
            .checked_mul(B_CONTINUOUS_FORMAL_CHUNK_SIZE as u64)
            == Some(transfer_size)
    });
    let full_transfer_matches_records = report
        .total_records_received
        .checked_mul(B_CONTINUOUS_FORMAL_CHUNK_SIZE as u64)
        == Some(report.total_application_bytes_received);

    report.mode == observation.participant.mode()
        && report.scheduler == MultipathScheduler::NoqDefault
        && report.congestion == QuicCongestion::Cubic
        && report.pto_recovery == PtoRecovery::Disabled
        && report.multipath_negotiated
        && report.data_intact
        && report.writer_alive_at_measurement_start
        && report.writer_alive_at_measurement_end
        && report.transfer_duration >= B_CONTINUOUS_FORMAL_MEASUREMENT
        && report.records_received_in_window > 0
        && transfer_matches_records
        && full_transfer_matches_records
        && report.total_records_received >= report.records_received_in_window
        && report.total_application_bytes_received >= report.transfer_size as u64
        && report.all_configured_paths_open
        && report.any_configured_path_open
        && mode_paths_pass
        && b_continuous_wire_ratio(report) <= B_CONTINUOUS_FORMAL_WIRE_RATIO_LIMIT
}

fn try_b_continuous_best_single_throughput(
    observations: &[BContinuousObservation],
    scenario: AggregationScenario,
    round: usize,
) -> Option<f64> {
    let line_one = find_b_continuous_observation(
        observations,
        scenario,
        round,
        BContinuousParticipant::LineOne,
    )?;
    let line_two = find_b_continuous_observation(
        observations,
        scenario,
        round,
        BContinuousParticipant::LineTwo,
    )?;
    if !b_continuous_participant_pass(line_one) || !b_continuous_participant_pass(line_two) {
        return None;
    }
    Some(
        line_one
            .report
            .throughput_mbps
            .max(line_two.report.throughput_mbps),
    )
}

fn b_continuous_best_single_ratio(
    observation: &BContinuousObservation,
    observations: &[BContinuousObservation],
) -> Option<f64> {
    (observation.participant == BContinuousParticipant::Multipath).then_some(())?;
    let best = try_b_continuous_best_single_throughput(
        observations,
        observation.scenario,
        observation.round,
    )?;
    (best > 0.0).then_some(observation.report.throughput_mbps / best)
}

fn b_continuous_round_pass(
    observations: &[BContinuousObservation],
    scenario: AggregationScenario,
    round: usize,
) -> bool {
    if BContinuousParticipant::ALL.into_iter().any(|participant| {
        observations
            .iter()
            .filter(|observation| {
                observation.scenario == scenario
                    && observation.round == round
                    && observation.participant == participant
            })
            .count()
            != 1
    }) {
        return false;
    }

    let all_participants_pass = BContinuousParticipant::ALL.into_iter().all(|participant| {
        find_b_continuous_observation(observations, scenario, round, participant)
            .is_some_and(b_continuous_participant_pass)
    });
    let Some(multipath) = find_b_continuous_observation(
        observations,
        scenario,
        round,
        BContinuousParticipant::Multipath,
    ) else {
        return false;
    };

    all_participants_pass
        && b_continuous_best_single_ratio(multipath, observations)
            .is_some_and(|ratio| ratio >= B_CONTINUOUS_FORMAL_GAIN_RATIO)
        && b_continuous_minimum_share_percent(&multipath.report)
            >= B_CONTINUOUS_FORMAL_MINIMUM_SHARE_PERCENT
        && multipath
            .report
            .both_paths_carried_minimum_effective_share()
}

fn b_continuous_scenario_pass(
    observations: &[BContinuousObservation],
    scenario: AggregationScenario,
) -> bool {
    let complete_rounds = (1..=SEED_PAIRS.len())
        .filter(|round| {
            BContinuousParticipant::ALL.into_iter().all(|participant| {
                find_b_continuous_observation(observations, scenario, *round, participant).is_some()
            })
        })
        .count();
    let passing_rounds = (1..=SEED_PAIRS.len())
        .filter(|round| b_continuous_round_pass(observations, scenario, *round))
        .count();
    complete_rounds == SEED_PAIRS.len() && passing_rounds >= 4
}

fn b_continuous_stage_pass(observations: &[BContinuousObservation]) -> bool {
    AggregationScenario::ALL
        .into_iter()
        .all(|scenario| b_continuous_scenario_pass(observations, scenario))
}

fn print_b_continuous_observation(
    observation: &BContinuousObservation,
    observations: &[BContinuousObservation],
) {
    println!(
        "- {}：{:.3} Mbit/s，接收记录 {}，线路一/二 fresh {} / {} 字节，重传 {} / {}，较少路径 {:.1}%，线速 {:.4}x，CPU {:.1}%，基础通过 {}",
        observation.participant.description(),
        observation.report.throughput_mbps,
        observation.report.records_received_in_window,
        observation.report.line_one.fresh_stream_bytes_sent,
        observation.report.line_two.fresh_stream_bytes_sent,
        observation.report.line_one.retransmitted_stream_bytes_sent,
        observation.report.line_two.retransmitted_stream_bytes_sent,
        b_continuous_minimum_share_percent(&observation.report),
        b_continuous_wire_ratio(&observation.report),
        observation.report.cpu_utilization_percent,
        yes_or_no(b_continuous_participant_pass(observation)),
    );
    if let Some(ratio) = b_continuous_best_single_ratio(observation, observations) {
        println!(
            "  相对当轮最佳单路 {:.1}%；本轮联合门槛 {}",
            ratio * 100.0,
            yes_or_no(b_continuous_round_pass(
                observations,
                observation.scenario,
                observation.round,
            )),
        );
    }
}

fn print_b_continuous_summary(observations: &[BContinuousObservation]) {
    println!();
    println!("持续单流正式 B 五种子汇总：");
    for scenario in AggregationScenario::ALL {
        println!();
        println!("场景：{}", scenario.description());
        for participant in BContinuousParticipant::ALL {
            let matching = observations
                .iter()
                .filter(|observation| {
                    observation.scenario == scenario && observation.participant == participant
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                continue;
            }
            let throughput = NumericSummary::from_samples(
                matching
                    .iter()
                    .map(|observation| observation.report.throughput_mbps),
            );
            println!(
                "- {}：吞吐中位 {:.3}，最差 {:.3}，范围 {:.3}～{:.3} Mbit/s",
                participant.description(),
                throughput.median,
                throughput.worst,
                throughput.minimum,
                throughput.maximum,
            );
        }

        let multipath = observations
            .iter()
            .filter(|observation| {
                observation.scenario == scenario
                    && observation.participant == BContinuousParticipant::Multipath
            })
            .collect::<Vec<_>>();
        if !multipath.is_empty() {
            let ratios = multipath
                .iter()
                .filter_map(|observation| b_continuous_best_single_ratio(observation, observations))
                .collect::<Vec<_>>();
            let shares = multipath
                .iter()
                .map(|observation| b_continuous_minimum_share_percent(&observation.report))
                .collect::<Vec<_>>();
            if !ratios.is_empty() {
                let ratio = NumericSummary::from_samples(ratios.iter().map(|ratio| ratio * 100.0));
                let share = NumericSummary::from_samples(shares);
                println!(
                    "  双路相对最佳单路：中位 {:.1}%，最差 {:.1}%；较少路径中位 {:.1}%，最差 {:.1}%",
                    ratio.median, ratio.worst, share.median, share.worst,
                );
            }
        }
        let passing_rounds = (1..=SEED_PAIRS.len())
            .filter(|round| b_continuous_round_pass(observations, scenario, *round))
            .count();
        println!(
            "  联合逐轮通过 {passing_rounds}/5；场景门槛 {}",
            yes_or_no(b_continuous_scenario_pass(observations, scenario)),
        );
    }
    println!(
        "两个场景联合门槛：{}",
        yes_or_no(b_continuous_stage_pass(observations)),
    );
}

fn verify_b_continuous_formal(observations: &[BContinuousObservation]) -> LabResult<()> {
    if b_continuous_stage_pass(observations) {
        println!("Cubic + NoQ 持续单流正式 B 门控通过；允许预注册 Hysteria B 公平对照。");
        return Ok(());
    }

    let failed = AggregationScenario::ALL
        .into_iter()
        .filter(|scenario| !b_continuous_scenario_pass(observations, *scenario))
        .map(|scenario| scenario.description())
        .collect::<Vec<_>>();
    Err(lab_error(format!(
        "Cubic + NoQ 持续单流正式 B 门控失败：{}；保留唯一 CSV，不得重跑或修改合同",
        failed.join("、"),
    )))
}

fn find_b_controller_observation(
    observations: &[BControllerObservation],
    scenario: AggregationScenario,
    participant: BControllerParticipant,
) -> Option<&BControllerObservation> {
    observations.iter().find(|observation| {
        observation.scenario == scenario && observation.participant == participant
    })
}

fn b_controller_single_retention_ratio(
    observations: &[BControllerObservation],
    scenario: AggregationScenario,
    participant: BControllerParticipant,
) -> Option<f64> {
    let baseline = match participant {
        BControllerParticipant::Bbr3LineOne => BControllerParticipant::CubicLineOne,
        BControllerParticipant::Bbr3LineTwo => BControllerParticipant::CubicLineTwo,
        _ => return None,
    };
    let baseline = find_b_controller_observation(observations, scenario, baseline)?
        .report
        .throughput_mbps;
    let candidate = find_b_controller_observation(observations, scenario, participant)?
        .report
        .throughput_mbps;
    (baseline > 0.0).then_some(candidate / baseline)
}

fn b_controller_best_single_throughput(
    observations: &[BControllerObservation],
    scenario: AggregationScenario,
) -> Option<f64> {
    const SINGLES: [BControllerParticipant; 4] = [
        BControllerParticipant::CubicLineOne,
        BControllerParticipant::CubicLineTwo,
        BControllerParticipant::Bbr3LineOne,
        BControllerParticipant::Bbr3LineTwo,
    ];

    let mut best = 0.0_f64;
    for participant in SINGLES {
        let throughput = find_b_controller_observation(observations, scenario, participant)?
            .report
            .throughput_mbps;
        best = best.max(throughput);
    }
    (best > 0.0).then_some(best)
}

fn b_controller_best_single_ratio(
    observations: &[BControllerObservation],
    scenario: AggregationScenario,
    participant: BControllerParticipant,
) -> Option<f64> {
    if participant != BControllerParticipant::Bbr3Multipath {
        return None;
    }
    let best_single = b_controller_best_single_throughput(observations, scenario)?;
    let multipath = find_b_controller_observation(observations, scenario, participant)?
        .report
        .throughput_mbps;
    Some(multipath / best_single)
}

fn b_controller_infrastructure_pass(observation: &BControllerObservation) -> bool {
    let report = &observation.report;
    report.mode == observation.participant.mode()
        && report.scheduler == MultipathScheduler::NoqDefault
        && report.congestion == observation.participant.congestion()
        && report.pto_recovery == PtoRecovery::Disabled
        && report.multipath_negotiated
        && report.transfer_size > 0
        && report.transfer_duration >= B_CONTROLLER_GATE_MEASUREMENT
        && report.any_configured_path_open
        && report.all_configured_paths_open
}

fn b_controller_participant_pass(
    observation: &BControllerObservation,
    observations: &[BControllerObservation],
) -> bool {
    if !b_controller_infrastructure_pass(observation) {
        return false;
    }

    match observation.participant {
        BControllerParticipant::CubicLineOne
        | BControllerParticipant::CubicLineTwo
        | BControllerParticipant::CubicMultipath => true,
        BControllerParticipant::Bbr3LineOne | BControllerParticipant::Bbr3LineTwo => {
            b_controller_single_retention_ratio(
                observations,
                observation.scenario,
                observation.participant,
            )
            .is_some_and(|ratio| ratio >= 0.95)
        }
        BControllerParticipant::Bbr3Multipath => {
            b_controller_best_single_ratio(
                observations,
                observation.scenario,
                observation.participant,
            )
            .is_some_and(|ratio| ratio >= 1.15)
                && minimum_effective_share_percent(&observation.report) >= 10.0
                && wire_ratio(&observation.report) <= 1.20
        }
    }
}

fn b_controller_stage_pass(
    observations: &[BControllerObservation],
    scenario: AggregationScenario,
) -> bool {
    observations
        .iter()
        .filter(|observation| observation.scenario == scenario)
        .count()
        == BControllerParticipant::ALL.len()
        && BControllerParticipant::ALL.into_iter().all(|participant| {
            find_b_controller_observation(observations, scenario, participant)
                .is_some_and(|observation| b_controller_participant_pass(observation, observations))
        })
}

fn print_b_controller_observation(
    observation: &BControllerObservation,
    observations: &[BControllerObservation],
) {
    let retention = b_controller_single_retention_ratio(
        observations,
        observation.scenario,
        observation.participant,
    )
    .map(|ratio| format!("；同线路 Cubic 保留率 {:.1}%", ratio * 100.0))
    .unwrap_or_default();
    let aggregation =
        b_controller_best_single_ratio(observations, observation.scenario, observation.participant)
            .map(|ratio| format!("；相对四项最佳单路 {:.1}%", ratio * 100.0))
            .unwrap_or_default();
    println!(
        "- {}：{:.3} Mbit/s；首次数据 {}/{}；重传 {}/{}；最小占比 {:.1}%；线速 {:.3}×；CPU {:.1}%；RSS {} KiB；开放 {}{retention}{aggregation}；参与项 {}",
        observation.participant.description(),
        observation.report.throughput_mbps,
        observation.report.line_one.fresh_stream_bytes_sent,
        observation.report.line_two.fresh_stream_bytes_sent,
        observation.report.line_one.retransmitted_stream_bytes_sent,
        observation.report.line_two.retransmitted_stream_bytes_sent,
        minimum_effective_share_percent(&observation.report),
        wire_ratio(&observation.report),
        observation.report.cpu_utilization_percent,
        observation.report.peak_rss_kib,
        yes_or_no(observation.report.all_configured_paths_open),
        yes_or_no(b_controller_participant_pass(observation, observations)),
    );
}

fn print_b_controller_summary(observations: &[BControllerObservation]) {
    println!();
    println!("BBR3 控制器联合门槛：");
    for scenario in AggregationScenario::ALL {
        let bbr3_line_one = find_b_controller_observation(
            observations,
            scenario,
            BControllerParticipant::Bbr3LineOne,
        )
        .expect("完整 smoke 必须包含 BBR3 线路一");
        let bbr3_line_two = find_b_controller_observation(
            observations,
            scenario,
            BControllerParticipant::Bbr3LineTwo,
        )
        .expect("完整 smoke 必须包含 BBR3 线路二");
        let bbr3_multipath = find_b_controller_observation(
            observations,
            scenario,
            BControllerParticipant::Bbr3Multipath,
        )
        .expect("完整 smoke 必须包含 BBR3 双路");
        let line_one_retention = b_controller_single_retention_ratio(
            observations,
            scenario,
            BControllerParticipant::Bbr3LineOne,
        )
        .expect("完整 smoke 必须能计算线路一保留率");
        let line_two_retention = b_controller_single_retention_ratio(
            observations,
            scenario,
            BControllerParticipant::Bbr3LineTwo,
        )
        .expect("完整 smoke 必须能计算线路二保留率");
        let best_single = b_controller_best_single_throughput(observations, scenario)
            .expect("完整 smoke 必须能计算最佳单路");
        let best_single_ratio = b_controller_best_single_ratio(
            observations,
            scenario,
            BControllerParticipant::Bbr3Multipath,
        )
        .expect("完整 smoke 必须能计算 BBR3 双路聚合比");

        println!(
            "- {}：BBR3 单路 {:.3}/{:.3} Mbit/s，Cubic 保留率 {:.1}%/{:.1}%；四项最佳单路 {:.3}，BBR3 双路 {:.3} Mbit/s（{:.1}%），最小占比 {:.1}%，线速 {:.3}×，双路开放 {}，阶段 {}",
            scenario.description(),
            bbr3_line_one.report.throughput_mbps,
            bbr3_line_two.report.throughput_mbps,
            line_one_retention * 100.0,
            line_two_retention * 100.0,
            best_single,
            bbr3_multipath.report.throughput_mbps,
            best_single_ratio * 100.0,
            minimum_effective_share_percent(&bbr3_multipath.report),
            wire_ratio(&bbr3_multipath.report),
            yes_or_no(bbr3_multipath.report.all_configured_paths_open),
            yes_or_no(b_controller_stage_pass(observations, scenario)),
        );
    }
}

fn verify_b_controller_gate(observations: &[BControllerObservation]) -> LabResult<()> {
    let failed = AggregationScenario::ALL
        .into_iter()
        .filter(|scenario| !b_controller_stage_pass(observations, *scenario))
        .map(|scenario| scenario.description())
        .collect::<Vec<_>>();

    if failed.is_empty() {
        println!("BBR3 最小控制器门控通过；允许预注册独立 formal 文件。");
        return Ok(());
    }

    Err(lab_error(format!(
        "BBR3 最小控制器门控失败：{}；保留 smoke CSV，不得重跑或进入 formal",
        failed.join("、")
    )))
}

fn find_b_declared_epoch_observation(
    observations: &[BDeclaredEpochObservation],
    scenario: AggregationScenario,
    participant: BDeclaredEpochParticipant,
) -> Option<&BDeclaredEpochObservation> {
    observations.iter().find(|observation| {
        observation.scenario == scenario && observation.participant == participant
    })
}

fn b_declared_epoch_rate_ratio(report: &DeclaredBackloggedEpochReport) -> Option<f64> {
    (report.throughput_mbps > 0.0)
        .then(|| report.path.declared_epoch_service_rate_mbps() / report.throughput_mbps)
}

fn b_declared_epoch_participant_pass(observation: &BDeclaredEpochObservation) -> bool {
    let report = &observation.report;
    let path = &report.path;
    report.mode == observation.participant.mode()
        && report.multipath_negotiated
        && report.data_intact
        && report.writer_alive_at_epoch_start
        && report.writer_alive_at_epoch_end
        && report.transfer_size > 0
        && report.transfer_duration >= B_DECLARED_EPOCH_MEASUREMENT
        && report.path_open
        && path.declared_epoch_cohorts == B_DECLARED_EPOCH_COHORTS
        && path.declared_epoch_settled_cohorts == B_DECLARED_EPOCH_COHORTS
        && path.declared_epoch_ack_coverage_ratio() >= 0.95
        && path.declared_epoch_late_ack_ratio() <= 0.05
        && path.declared_epoch_pending_cohorts == 0
        && path.declared_epoch_pending_origin_bytes == 0
        && path.declared_epoch_tracked_origin_bytes == 0
        && b_declared_epoch_rate_ratio(report).is_some_and(|ratio| (0.85..=1.15).contains(&ratio))
}

fn b_declared_epoch_stage_pass(
    observations: &[BDeclaredEpochObservation],
    scenario: AggregationScenario,
) -> bool {
    let Some(line_one) = find_b_declared_epoch_observation(
        observations,
        scenario,
        BDeclaredEpochParticipant::LineOne,
    ) else {
        return false;
    };
    let Some(line_two) = find_b_declared_epoch_observation(
        observations,
        scenario,
        BDeclaredEpochParticipant::LineTwo,
    ) else {
        return false;
    };
    if !b_declared_epoch_participant_pass(line_one) || !b_declared_epoch_participant_pass(line_two)
    {
        return false;
    }

    let service_one = line_one.report.path.declared_epoch_service_rate_mbps();
    let service_two = line_two.report.path.declared_epoch_service_rate_mbps();
    match scenario {
        AggregationScenario::Balanced => {
            let maximum = service_one.max(service_two);
            maximum > 0.0 && service_one.min(service_two) / maximum >= 0.85
        }
        AggregationScenario::Heterogeneous => {
            service_one > 0.0
                && line_one.report.throughput_mbps > 0.0
                && service_two / service_one >= 2.0
                && line_two.report.throughput_mbps / line_one.report.throughput_mbps >= 2.0
        }
    }
}

fn print_b_declared_epoch_observation(
    observation: &BDeclaredEpochObservation,
    observations: &[BDeclaredEpochObservation],
) {
    let report = &observation.report;
    let path = &report.path;
    println!(
        "- {}：业务 {:.3} Mbit/s，传感器 {:.3} Mbit/s（{:.1}%）；cohort 声明/结算/空窗 {}/{}/{}，及时确认 {:.1}%，迟到 {:.2}%，drain 缺失 {}，待结算/待确认/保留 {}/{}/{}；writer 起止 {}/{}，CPU {:.1}%，RSS {} KiB，参与项 {}，阶段 {}",
        observation.participant.description(),
        report.throughput_mbps,
        path.declared_epoch_service_rate_mbps(),
        b_declared_epoch_rate_ratio(report).unwrap_or_default() * 100.0,
        path.declared_epoch_cohorts,
        path.declared_epoch_settled_cohorts,
        path.declared_epoch_empty_cohorts,
        path.declared_epoch_ack_coverage_ratio() * 100.0,
        path.declared_epoch_late_ack_ratio() * 100.0,
        path.declared_epoch_bytes_missing_at_drain,
        path.declared_epoch_pending_cohorts,
        path.declared_epoch_pending_origin_bytes,
        path.declared_epoch_tracked_origin_bytes,
        yes_or_no(report.writer_alive_at_epoch_start),
        yes_or_no(report.writer_alive_at_epoch_end),
        report.cpu_utilization_percent,
        report.peak_rss_kib,
        yes_or_no(b_declared_epoch_participant_pass(observation)),
        yes_or_no(b_declared_epoch_stage_pass(
            observations,
            observation.scenario,
        )),
    );
}

fn print_b_declared_epoch_summary(observations: &[BDeclaredEpochObservation]) {
    println!();
    println!("declared backlogged epoch 联合门槛：");
    for scenario in AggregationScenario::ALL {
        let line_one = find_b_declared_epoch_observation(
            observations,
            scenario,
            BDeclaredEpochParticipant::LineOne,
        )
        .expect("完整 smoke 必须包含线路一");
        let line_two = find_b_declared_epoch_observation(
            observations,
            scenario,
            BDeclaredEpochParticipant::LineTwo,
        )
        .expect("完整 smoke 必须包含线路二");
        let service_one = line_one.report.path.declared_epoch_service_rate_mbps();
        let service_two = line_two.report.path.declared_epoch_service_rate_mbps();
        println!(
            "- {}：业务 {:.3}/{:.3} Mbit/s（线路二/一 {:.3}x），传感器 {:.3}/{:.3} Mbit/s（线路二/一 {:.3}x），阶段 {}",
            scenario.description(),
            line_one.report.throughput_mbps,
            line_two.report.throughput_mbps,
            line_two.report.throughput_mbps / line_one.report.throughput_mbps,
            service_one,
            service_two,
            service_two / service_one,
            yes_or_no(b_declared_epoch_stage_pass(observations, scenario)),
        );
    }
}

fn verify_b_declared_epoch_gate(observations: &[BDeclaredEpochObservation]) -> LabResult<()> {
    let failed = AggregationScenario::ALL
        .into_iter()
        .filter(|scenario| !b_declared_epoch_stage_pass(observations, *scenario))
        .map(AggregationScenario::description)
        .collect::<Vec<_>>();
    if failed.is_empty() {
        println!("declared backlogged epoch 门控通过；允许另名预注册双路训练候选。");
        return Ok(());
    }
    Err(lab_error(format!(
        "declared backlogged epoch 门控失败：{}；保留唯一 smoke，不得重跑或接入权重",
        failed.join("、")
    )))
}

fn write_b_continuous_csv(path: &str, observations: &[BContinuousObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "scenario,round,line_one_seed,line_two_seed,participant,congestion,mode,scheduler,pto_recovery,warmup_ms,measurement_ms,chunk_size_bytes,data_intact,writer_alive_at_measurement_start,writer_alive_at_measurement_end,throughput_mbps,records_received_in_window,transfer_bytes,transfer_ms,total_records_received,total_application_bytes_received,line_one_fresh_bytes,line_two_fresh_bytes,line_one_retransmit_bytes,line_two_retransmit_bytes,minimum_effective_share_percent,total_udp_bytes,extra_udp_bytes,wire_ratio,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,multipath_negotiated,any_configured_path_open,all_configured_paths_open,best_single_ratio,participant_pass,round_pass,scenario_pass,stage_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.scenario.description().to_owned(),
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            observation.participant.description().to_owned(),
            report.congestion.description().to_owned(),
            report.mode.description().to_owned(),
            report.scheduler.description().to_owned(),
            report.pto_recovery.description().to_owned(),
            B_CONTINUOUS_FORMAL_WARMUP.as_millis().to_string(),
            B_CONTINUOUS_FORMAL_MEASUREMENT.as_millis().to_string(),
            B_CONTINUOUS_FORMAL_CHUNK_SIZE.to_string(),
            report.data_intact.to_string(),
            report.writer_alive_at_measurement_start.to_string(),
            report.writer_alive_at_measurement_end.to_string(),
            format!("{:.6}", report.throughput_mbps),
            report.records_received_in_window.to_string(),
            report.transfer_size.to_string(),
            format!("{:.3}", milliseconds(report.transfer_duration)),
            report.total_records_received.to_string(),
            report.total_application_bytes_received.to_string(),
            report.line_one.fresh_stream_bytes_sent.to_string(),
            report.line_two.fresh_stream_bytes_sent.to_string(),
            report.line_one.retransmitted_stream_bytes_sent.to_string(),
            report.line_two.retransmitted_stream_bytes_sent.to_string(),
            format!(
                "{:.6}",
                b_continuous_minimum_share_percent(&observation.report)
            ),
            report.total_udp_bytes_sent.to_string(),
            report.extra_udp_bytes_sent.to_string(),
            format!("{:.6}", b_continuous_wire_ratio(report)),
            format!("{:.3}", milliseconds(report.cpu_time)),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.multipath_negotiated.to_string(),
            report.any_configured_path_open.to_string(),
            report.all_configured_paths_open.to_string(),
            csv_optional_ratio(b_continuous_best_single_ratio(observation, observations)),
            b_continuous_participant_pass(observation).to_string(),
            b_continuous_round_pass(observations, observation.scenario, observation.round)
                .to_string(),
            b_continuous_scenario_pass(observations, observation.scenario).to_string(),
            b_continuous_stage_pass(observations).to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_b_declared_epoch_csv(
    path: &str,
    observations: &[BDeclaredEpochObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "scenario,round,line_one_seed,line_two_seed,participant,congestion,mode,scheduler,pto_recovery,warmup_ms,measurement_ms,chunk_size_bytes,data_intact,writer_alive_at_epoch_start,writer_alive_at_epoch_end,throughput_mbps,transfer_bytes,transfer_ms,sensor_service_mbps,sensor_to_throughput_ratio,declared_cohorts,settled_cohorts,empty_cohorts,epoch_fresh_bytes,epoch_acked_bytes,ack_coverage_ratio,late_acked_bytes,late_ack_ratio,bytes_missing_at_drain,pending_cohorts,pending_origin_bytes,tracked_origin_bytes,fresh_stream_bytes,retransmit_stream_bytes,total_udp_bytes,wire_ratio,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,multipath_negotiated,path_open,participant_pass,stage_pass\n",
    );
    for observation in observations {
        let report = &observation.report;
        let path = &report.path;
        let wire_ratio = if report.transfer_size == 0 {
            0.0
        } else {
            report.total_udp_bytes_sent as f64 / report.transfer_size as f64
        };
        let fields = vec![
            observation.scenario.description().to_owned(),
            "1".to_owned(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            observation.participant.description().to_owned(),
            QuicCongestion::Cubic.description().to_owned(),
            report.mode.description().to_owned(),
            MultipathScheduler::NoqDefault.description().to_owned(),
            PtoRecovery::Disabled.description().to_owned(),
            B_DECLARED_EPOCH_WARMUP.as_millis().to_string(),
            B_DECLARED_EPOCH_MEASUREMENT.as_millis().to_string(),
            B_DECLARED_EPOCH_CHUNK_SIZE.to_string(),
            report.data_intact.to_string(),
            report.writer_alive_at_epoch_start.to_string(),
            report.writer_alive_at_epoch_end.to_string(),
            format!("{:.6}", report.throughput_mbps),
            report.transfer_size.to_string(),
            report.transfer_duration.as_millis().to_string(),
            format!("{:.6}", path.declared_epoch_service_rate_mbps()),
            format!(
                "{:.6}",
                b_declared_epoch_rate_ratio(report).unwrap_or_default()
            ),
            path.declared_epoch_cohorts.to_string(),
            path.declared_epoch_settled_cohorts.to_string(),
            path.declared_epoch_empty_cohorts.to_string(),
            path.declared_epoch_fresh_bytes.to_string(),
            path.declared_epoch_acked_bytes.to_string(),
            format!("{:.6}", path.declared_epoch_ack_coverage_ratio()),
            path.declared_epoch_late_acked_bytes.to_string(),
            format!("{:.6}", path.declared_epoch_late_ack_ratio()),
            path.declared_epoch_bytes_missing_at_drain.to_string(),
            path.declared_epoch_pending_cohorts.to_string(),
            path.declared_epoch_pending_origin_bytes.to_string(),
            path.declared_epoch_tracked_origin_bytes.to_string(),
            path.fresh_stream_bytes_sent.to_string(),
            path.retransmitted_stream_bytes_sent.to_string(),
            report.total_udp_bytes_sent.to_string(),
            format!("{wire_ratio:.6}"),
            report.cpu_time.as_millis().to_string(),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.multipath_negotiated.to_string(),
            report.path_open.to_string(),
            b_declared_epoch_participant_pass(observation).to_string(),
            b_declared_epoch_stage_pass(observations, observation.scenario).to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }
    fs::write(path, csv)?;
    Ok(())
}

fn csv_optional_ratio(value: Option<f64>) -> String {
    value.map(|ratio| format!("{ratio:.6}")).unwrap_or_default()
}

fn write_b_controller_csv(path: &str, observations: &[BControllerObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "scenario,round,line_one_seed,line_two_seed,participant,congestion,mode,scheduler,pto_recovery,warmup_ms,measurement_ms,chunk_size_bytes,throughput_mbps,transfer_bytes,transfer_ms,line_one_fresh_bytes,line_two_fresh_bytes,line_one_retransmit_bytes,line_two_retransmit_bytes,minimum_effective_share_percent,total_udp_bytes,wire_ratio,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,multipath_negotiated,any_configured_path_open,all_configured_paths_open,single_retention_ratio,best_single_ratio,participant_pass,stage_pass\n",
    );

    for observation in observations {
        let fields = vec![
            observation.scenario.description().to_owned(),
            "1".to_owned(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            observation.participant.description().to_owned(),
            observation.report.congestion.description().to_owned(),
            observation.report.mode.description().to_owned(),
            observation.report.scheduler.description().to_owned(),
            observation.report.pto_recovery.description().to_owned(),
            B_CONTROLLER_GATE_WARMUP.as_millis().to_string(),
            B_CONTROLLER_GATE_MEASUREMENT.as_millis().to_string(),
            B_CONTROLLER_GATE_CHUNK_SIZE.to_string(),
            format!("{:.6}", observation.report.throughput_mbps),
            observation.report.transfer_size.to_string(),
            format!("{:.3}", milliseconds(observation.report.transfer_duration)),
            observation
                .report
                .line_one
                .fresh_stream_bytes_sent
                .to_string(),
            observation
                .report
                .line_two
                .fresh_stream_bytes_sent
                .to_string(),
            observation
                .report
                .line_one
                .retransmitted_stream_bytes_sent
                .to_string(),
            observation
                .report
                .line_two
                .retransmitted_stream_bytes_sent
                .to_string(),
            format!(
                "{:.6}",
                minimum_effective_share_percent(&observation.report)
            ),
            observation.report.total_udp_bytes_sent.to_string(),
            format!("{:.6}", wire_ratio(&observation.report)),
            format!("{:.3}", milliseconds(observation.report.cpu_time)),
            format!("{:.6}", observation.report.cpu_utilization_percent),
            observation.report.peak_rss_kib.to_string(),
            observation.report.multipath_negotiated.to_string(),
            observation.report.any_configured_path_open.to_string(),
            observation.report.all_configured_paths_open.to_string(),
            csv_optional_ratio(b_controller_single_retention_ratio(
                observations,
                observation.scenario,
                observation.participant,
            )),
            csv_optional_ratio(b_controller_best_single_ratio(
                observations,
                observation.scenario,
                observation.participant,
            )),
            b_controller_participant_pass(observation, observations).to_string(),
            b_controller_stage_pass(observations, observation.scenario).to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_benchmark_csv(path: &str, observations: &[ScreeningObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "scenario,round,line_one_seed,line_two_seed,participant,pto_recovery,throughput_mbps,transfer_ms,line_one_fresh_bytes,line_two_fresh_bytes,line_one_retransmit_bytes,line_two_retransmit_bytes,total_udp_bytes,wire_ratio,minimum_effective_share_percent,best_single_ratio,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,line_one_pto_hedges,line_two_pto_hedges,line_one_pto_hedge_bytes,line_two_pto_hedge_bytes,any_configured_path_open,all_configured_paths_open\n",
    );

    for observation in observations {
        let best_single_ratio = match observation.participant {
            ScreeningParticipant::Multipath(_) => {
                try_best_single_throughput(observations, observation.scenario, observation.round)
                    .map(|best_single| observation.report.throughput_mbps / best_single)
            }
            ScreeningParticipant::LineOne | ScreeningParticipant::LineTwo => None,
        }
        .map(|ratio| format!("{ratio:.6}"))
        .unwrap_or_default();
        writeln!(
            csv,
            "{},{},{},{},{},{},{:.6},{:.3},{},{},{},{},{},{:.6},{:.6},{},{:.3},{:.6},{},{},{},{},{},{},{}",
            observation.scenario.description(),
            observation.round,
            observation.seeds.line_one,
            observation.seeds.line_two,
            observation.participant.description(),
            observation.report.pto_recovery.description(),
            observation.report.throughput_mbps,
            milliseconds(observation.report.transfer_duration),
            observation.report.line_one.fresh_stream_bytes_sent,
            observation.report.line_two.fresh_stream_bytes_sent,
            observation.report.line_one.retransmitted_stream_bytes_sent,
            observation.report.line_two.retransmitted_stream_bytes_sent,
            observation.report.total_udp_bytes_sent,
            wire_ratio(&observation.report),
            minimum_effective_share_percent(&observation.report),
            best_single_ratio,
            milliseconds(observation.report.cpu_time),
            observation.report.cpu_utilization_percent,
            observation.report.peak_rss_kib,
            observation.report.line_one.pto_hedges,
            observation.report.line_two.pto_hedges,
            observation.report.line_one.pto_hedge_bytes,
            observation.report.line_two.pto_hedge_bytes,
            observation.report.any_configured_path_open,
            observation.report.all_configured_paths_open,
        )?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_realtime_csv(path: &str, observations: &[RealtimeObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,duration_ms,measurement_elapsed_ms,logical_messages,batches,queued_copy_datagrams,observed_copy_datagrams,decoded_copy_datagrams,valid_messages,late_messages,lost_messages,duplicate_messages,error_messages,malformed_copy_datagrams,invalid_batch_messages,invalid_sequence_messages,timestamp_error_messages,digest_error_messages,content_error_messages,effective_arrival_percent,p50_ms,p95_ms,p99_ms,logical_application_bytes,line_one_udp_bytes_sent,line_two_udp_bytes_sent,total_udp_bytes_sent,udp_wire_ratio,line_one_udp_datagrams_sent,line_two_udp_datagrams_sent,line_one_datagram_frames_sent,line_two_datagram_frames_sent,copies_used_distinct_paths,measurement_is_complete,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,primary_path_open,secondary_path_open,smoke_safety_pass,stage_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            format!("{:.3}", milliseconds(report.duration)),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.logical_messages.to_string(),
            report.batches.to_string(),
            report.queued_copy_datagrams.to_string(),
            report.observed_copy_datagrams.to_string(),
            report.decoded_copy_datagrams.to_string(),
            report.valid_messages.to_string(),
            report.late_messages.to_string(),
            report.lost_messages.to_string(),
            report.duplicate_messages.to_string(),
            report.error_messages.to_string(),
            report.malformed_copy_datagrams.to_string(),
            report.invalid_batch_messages.to_string(),
            report.invalid_sequence_messages.to_string(),
            report.timestamp_error_messages.to_string(),
            report.digest_error_messages.to_string(),
            report.content_error_messages.to_string(),
            format!("{:.6}", report.effective_arrival_percent()),
            csv_optional_milliseconds(report.p50),
            csv_optional_milliseconds(report.p95),
            csv_optional_milliseconds(report.p99),
            report.logical_application_bytes.to_string(),
            report.line_one_udp_bytes_sent.to_string(),
            report.line_two_udp_bytes_sent.to_string(),
            report.total_udp_bytes_sent.to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            report.line_one_udp_datagrams_sent.to_string(),
            report.line_two_udp_datagrams_sent.to_string(),
            report.line_one_datagram_frames_sent.to_string(),
            report.line_two_datagram_frames_sent.to_string(),
            report.copies_used_distinct_paths().to_string(),
            report.measurement_is_complete().to_string(),
            format!("{:.3}", milliseconds(report.cpu_time)),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.primary_path_open.to_string(),
            report.secondary_path_open.to_string(),
            report.smoke_safety_pass().to_string(),
            report.stage_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_realtime_v3_wire_csv(
    path: &str,
    observations: &[RealtimeV3WireObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,duration_ms,measurement_elapsed_ms,logical_messages,blocks,queued_original_frames,queued_pair_parity_frames,queued_global_parity_frames,isolation_confirmations,observed_frames,decoded_frames,observed_original_frames,observed_pair_parity_frames,observed_global_zero_frames,observed_global_one_frames,duplicate_original_frames,error_frames,malformed_frames,invalid_header_frames,digest_error_frames,content_error_frames,timestamp_error_frames,original_p50_ms,original_p95_ms,original_p99_ms,logical_application_bytes,line_one_udp_bytes_sent,line_two_udp_bytes_sent,total_udp_bytes_sent,udp_wire_ratio,line_one_udp_datagrams_sent,line_two_udp_datagrams_sent,line_one_datagram_frames_sent,line_two_datagram_frames_sent,frames_exactly_routed,frames_isolated,measurement_is_complete,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,primary_path_open,secondary_path_open,wire_latency_gate_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            format!("{:.3}", milliseconds(report.duration)),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.logical_messages.to_string(),
            report.blocks.to_string(),
            report.queued_original_frames.to_string(),
            report.queued_pair_parity_frames.to_string(),
            report.queued_global_parity_frames.to_string(),
            report.isolation_confirmations.to_string(),
            report.observed_frames.to_string(),
            report.decoded_frames.to_string(),
            report.observed_original_frames.to_string(),
            report.observed_pair_parity_frames.to_string(),
            report.observed_global_zero_frames.to_string(),
            report.observed_global_one_frames.to_string(),
            report.duplicate_original_frames.to_string(),
            report.error_frames().to_string(),
            report.malformed_frames.to_string(),
            report.invalid_header_frames.to_string(),
            report.digest_error_frames.to_string(),
            report.content_error_frames.to_string(),
            report.timestamp_error_frames.to_string(),
            csv_optional_milliseconds(report.original_p50),
            csv_optional_milliseconds(report.original_p95),
            csv_optional_milliseconds(report.original_p99),
            report.logical_application_bytes.to_string(),
            report.line_one_udp_bytes_sent.to_string(),
            report.line_two_udp_bytes_sent.to_string(),
            report.total_udp_bytes_sent.to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            report.line_one_udp_datagrams_sent.to_string(),
            report.line_two_udp_datagrams_sent.to_string(),
            report.line_one_datagram_frames_sent.to_string(),
            report.line_two_datagram_frames_sent.to_string(),
            report.frames_exactly_routed().to_string(),
            report.frames_isolated().to_string(),
            report.measurement_is_complete().to_string(),
            format!("{:.3}", milliseconds(report.cpu_time)),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.primary_path_open.to_string(),
            report.secondary_path_open.to_string(),
            report.wire_latency_gate_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_realtime_controller_gate_csv(
    path: &str,
    observations: &[RealtimeControllerGateObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,congestion,duration_ms,measurement_elapsed_ms,logical_messages,queued_frames,observed_frames,decoded_frames,valid_messages,late_messages,lost_messages,duplicate_messages,error_frames,malformed_frames,invalid_sequence_frames,timestamp_error_frames,digest_error_frames,content_error_frames,p50_ms,p95_ms,p99_ms,logical_application_bytes,line_one_udp_bytes_sent,line_two_udp_bytes_sent,total_udp_bytes_sent,udp_wire_ratio,line_one_udp_datagrams_sent,line_two_udp_datagrams_sent,line_one_datagram_frames_sent,line_two_datagram_frames_sent,frames_exactly_routed,measurement_is_complete,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,primary_path_open,secondary_path_open,feasibility_gate_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            report.congestion.description().to_owned(),
            format!("{:.3}", milliseconds(report.duration)),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.logical_messages.to_string(),
            report.queued_frames.to_string(),
            report.observed_frames.to_string(),
            report.decoded_frames.to_string(),
            report.valid_messages.to_string(),
            report.late_messages.to_string(),
            report.lost_messages.to_string(),
            report.duplicate_messages.to_string(),
            report.error_frames().to_string(),
            report.malformed_frames.to_string(),
            report.invalid_sequence_frames.to_string(),
            report.timestamp_error_frames.to_string(),
            report.digest_error_frames.to_string(),
            report.content_error_frames.to_string(),
            csv_optional_milliseconds(report.p50),
            csv_optional_milliseconds(report.p95),
            csv_optional_milliseconds(report.p99),
            report.logical_application_bytes.to_string(),
            report.line_one_udp_bytes_sent.to_string(),
            report.line_two_udp_bytes_sent.to_string(),
            report.total_udp_bytes_sent.to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            report.line_one_udp_datagrams_sent.to_string(),
            report.line_two_udp_datagrams_sent.to_string(),
            report.line_one_datagram_frames_sent.to_string(),
            report.line_two_datagram_frames_sent.to_string(),
            report.frames_exactly_routed().to_string(),
            report.measurement_is_complete().to_string(),
            format!("{:.3}", milliseconds(report.cpu_time)),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.primary_path_open.to_string(),
            report.secondary_path_open.to_string(),
            report.feasibility_gate_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_realtime_v4_csv(path: &str, observations: &[RealtimeV4Observation]) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,congestion,duration_ms,measurement_elapsed_ms,logical_messages,blocks,queued_original_frames,queued_pair_parity_frames,queued_global_parity_frames,observed_frames,decoded_frames,observed_original_frames,observed_pair_parity_frames,observed_global_zero_frames,observed_global_one_frames,original_deliveries,pair_recoveries,global_recoveries,valid_messages,late_messages,lost_messages,duplicate_messages,error_messages,malformed_frames,invalid_header_frames,digest_error_frames,content_error_frames,recovery_error_messages,timestamp_error_messages,effective_arrival_percent,p50_ms,p95_ms,p99_ms,logical_application_bytes,line_one_udp_bytes_sent,line_two_udp_bytes_sent,total_udp_bytes_sent,udp_wire_ratio,line_one_udp_datagrams_sent,line_two_udp_datagrams_sent,line_one_datagram_frames_sent,line_two_datagram_frames_sent,frames_exactly_routed,application_frames_are_separate,measurement_is_complete,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,primary_path_open,secondary_path_open,safety_pass,stage_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            "BBR3".to_owned(),
            format!("{:.3}", milliseconds(report.duration)),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.logical_messages.to_string(),
            report.blocks.to_string(),
            report.queued_original_frames.to_string(),
            report.queued_pair_parity_frames.to_string(),
            report.queued_global_parity_frames.to_string(),
            report.observed_frames.to_string(),
            report.decoded_frames.to_string(),
            report.observed_original_frames.to_string(),
            report.observed_pair_parity_frames.to_string(),
            report.observed_global_zero_frames.to_string(),
            report.observed_global_one_frames.to_string(),
            report.original_deliveries.to_string(),
            report.pair_recoveries.to_string(),
            report.global_recoveries.to_string(),
            report.valid_messages.to_string(),
            report.late_messages.to_string(),
            report.lost_messages.to_string(),
            report.duplicate_messages.to_string(),
            report.error_messages().to_string(),
            report.malformed_frames.to_string(),
            report.invalid_header_frames.to_string(),
            report.digest_error_frames.to_string(),
            report.content_error_frames.to_string(),
            report.recovery_error_messages.to_string(),
            report.timestamp_error_messages.to_string(),
            format!("{:.6}", report.effective_arrival_percent()),
            csv_optional_milliseconds(report.p50),
            csv_optional_milliseconds(report.p95),
            csv_optional_milliseconds(report.p99),
            report.logical_application_bytes.to_string(),
            report.line_one_udp_bytes_sent.to_string(),
            report.line_two_udp_bytes_sent.to_string(),
            report.total_udp_bytes_sent.to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            report.line_one_udp_datagrams_sent.to_string(),
            report.line_two_udp_datagrams_sent.to_string(),
            report.line_one_datagram_frames_sent.to_string(),
            report.line_two_datagram_frames_sent.to_string(),
            report.frames_exactly_routed().to_string(),
            report.application_frames_are_separate().to_string(),
            report.measurement_is_complete().to_string(),
            format!("{:.3}", milliseconds(report.cpu_time)),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.primary_path_open.to_string(),
            report.secondary_path_open.to_string(),
            report.safety_pass().to_string(),
            report.stage_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_realtime_v12_csv(path: &str, observations: &[RealtimeV12Observation]) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,congestion,duration_ms,measurement_elapsed_ms,logical_messages,superblocks,frame_size_bytes,header_size_bytes,shard_size_bytes,queued_data0_frames,queued_data1_frames,queued_local_parity_frames,queued_global_parity_frames,observed_frames,decoded_frames,observed_data0_frames,observed_data1_frames,observed_local_parity_frames,observed_global_row_0_frames,observed_global_row_1_frames,observed_global_row_2_frames,systematic_deliveries,local_xor_recoveries,global_recoveries,valid_messages,late_messages,lost_messages,duplicate_shard_frames,error_messages,malformed_frames,invalid_header_frames,digest_error_frames,content_error_frames,recovery_error_messages,timestamp_error_messages,effective_arrival_percent,p50_ms,p95_ms,p99_ms,logical_application_bytes,line_one_udp_bytes_sent,line_two_udp_bytes_sent,total_udp_bytes_sent,udp_wire_ratio,line_one_udp_datagrams_sent,line_two_udp_datagrams_sent,line_one_datagram_frames_sent,line_two_datagram_frames_sent,frames_exactly_routed,application_frames_are_separate,segmentation_offload_enabled,nonzero_superblock_accounting_test,two_of_three_accounting_test,measurement_is_complete,cpu_time_ms,cpu_utilization_percent,peak_rss_kib,primary_path_open,secondary_path_open,safety_pass,stage_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            "BBR3".to_owned(),
            format!("{:.3}", milliseconds(report.duration)),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.logical_messages.to_string(),
            report.blocks.to_string(),
            report.frame_size_bytes.to_string(),
            report.header_size_bytes.to_string(),
            report.shard_size_bytes.to_string(),
            report.queued_data0_frames.to_string(),
            report.queued_data1_frames.to_string(),
            report.queued_local_parity_frames.to_string(),
            report.queued_global_parity_frames.to_string(),
            report.observed_frames.to_string(),
            report.decoded_frames.to_string(),
            report.observed_data0_frames.to_string(),
            report.observed_data1_frames.to_string(),
            report.observed_local_parity_frames.to_string(),
            report.observed_global_row_0_frames.to_string(),
            report.observed_global_row_1_frames.to_string(),
            report.observed_global_row_2_frames.to_string(),
            report.systematic_deliveries.to_string(),
            report.local_xor_recoveries.to_string(),
            report.global_recoveries.to_string(),
            report.valid_messages.to_string(),
            report.late_messages.to_string(),
            report.lost_messages.to_string(),
            report.duplicate_shard_frames.to_string(),
            report.error_messages().to_string(),
            report.malformed_frames.to_string(),
            report.invalid_header_frames.to_string(),
            report.digest_error_frames.to_string(),
            report.content_error_frames.to_string(),
            report.recovery_error_messages.to_string(),
            report.timestamp_error_messages.to_string(),
            format!("{:.6}", report.effective_arrival_percent()),
            csv_optional_milliseconds(report.p50),
            csv_optional_milliseconds(report.p95),
            csv_optional_milliseconds(report.p99),
            report.logical_application_bytes.to_string(),
            report.line_one_udp_bytes_sent.to_string(),
            report.line_two_udp_bytes_sent.to_string(),
            report.total_udp_bytes_sent.to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            report.line_one_udp_datagrams_sent.to_string(),
            report.line_two_udp_datagrams_sent.to_string(),
            report.line_one_datagram_frames_sent.to_string(),
            report.line_two_datagram_frames_sent.to_string(),
            report.frames_exactly_routed().to_string(),
            report.application_frames_are_separate().to_string(),
            report.segmentation_offload_enabled.to_string(),
            report.nonzero_superblock_accounting_test.to_string(),
            report.two_of_three_accounting_test.to_string(),
            report.measurement_is_complete().to_string(),
            format!("{:.3}", milliseconds(report.cpu_time)),
            format!("{:.6}", report.cpu_utilization_percent),
            report.peak_rss_kib.to_string(),
            report.primary_path_open.to_string(),
            report.secondary_path_open.to_string(),
            report.safety_pass().to_string(),
            report.stage_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_hysteria_throughput_csv(
    path: &str,
    observations: &[HysteriaThroughputObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "scenario,round,line_one_seed,line_two_seed,payload_seed,congestion,line,configured_bandwidth_mbps,warmup_ms,measurement_ms,chunk_size_bytes,data_intact,exchange_complete,writer_alive_at_measurement_start,writer_alive_at_measurement_end,records_received_in_window,application_bytes_received_in_window,measurement_elapsed_ms,throughput_mbps,total_records_received,total_application_bytes_received,client_line_one_udp_payload_bytes,client_line_two_udp_payload_bytes,server_line_one_udp_payload_bytes,server_line_two_udp_payload_bytes,client_line_one_packets,client_line_two_packets,server_line_one_packets,server_line_two_packets,target_client_udp_payload_bytes,target_server_udp_payload_bytes,non_target_udp_payload_bytes,udp_wire_ratio,extra_wire_ratio,processes_alive_at_end,infrastructure_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.scenario.description().to_owned(),
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            observation.payload_seed.to_string(),
            report.congestion.description().to_owned(),
            report.line.description().to_owned(),
            report.bandwidth_mbps.to_string(),
            report.warmup_duration.as_millis().to_string(),
            report.measurement_duration.as_millis().to_string(),
            report.chunk_size.to_string(),
            report.data_intact.to_string(),
            report.exchange_complete.to_string(),
            report.writer_alive_at_measurement_start.to_string(),
            report.writer_alive_at_measurement_end.to_string(),
            report.records_received_in_window.to_string(),
            report.application_bytes_received_in_window.to_string(),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            format!("{:.6}", report.throughput_mbps),
            report.total_records_received.to_string(),
            report.total_application_bytes_received.to_string(),
            report.client_line_one_udp_payload_bytes.to_string(),
            report.client_line_two_udp_payload_bytes.to_string(),
            report.server_line_one_udp_payload_bytes.to_string(),
            report.server_line_two_udp_payload_bytes.to_string(),
            report.client_line_one_packets.to_string(),
            report.client_line_two_packets.to_string(),
            report.server_line_one_packets.to_string(),
            report.server_line_two_packets.to_string(),
            report.target_client_udp_payload_bytes().to_string(),
            report.target_server_udp_payload_bytes().to_string(),
            report.non_target_udp_payload_bytes().to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            format!("{:.6}", report.extra_wire_ratio()),
            report.processes_alive_at_end.to_string(),
            report.infrastructure_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_hysteria_realtime_csv(
    path: &str,
    observations: &[HysteriaRealtimeObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,hysteria_version,hysteria_sha256,congestion,line,duration_ms,measurement_elapsed_ms,logical_messages,observed_datagrams,decoded_datagrams,valid_messages,late_messages,lost_messages,duplicate_messages,error_messages,malformed_messages,invalid_sequence_messages,digest_error_messages,content_error_messages,effective_arrival_percent,p50_ms,p95_ms,p99_ms,logical_application_bytes,line_one_udp_payload_bytes,line_two_udp_payload_bytes,total_udp_payload_bytes,udp_wire_ratio,line_one_client_packets,line_two_client_packets,tls_exact_validation,obfs_enabled,processes_alive_at_end,measurement_is_complete,used_only_target_line,smoke_safety_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            "2.9.3".to_owned(),
            "66dbdb0608f25f3057b433afe975a9fc1af2ca8e512479e294988b3ef363d6c1".to_owned(),
            report.congestion.description().to_owned(),
            report.line.description().to_owned(),
            format!("{:.3}", milliseconds(report.duration)),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.logical_messages.to_string(),
            report.observed_datagrams.to_string(),
            report.decoded_datagrams.to_string(),
            report.valid_messages.to_string(),
            report.late_messages.to_string(),
            report.lost_messages.to_string(),
            report.duplicate_messages.to_string(),
            report.error_messages().to_string(),
            report.malformed_messages.to_string(),
            report.invalid_sequence_messages.to_string(),
            report.digest_error_messages.to_string(),
            report.content_error_messages.to_string(),
            format!("{:.6}", report.effective_arrival_percent()),
            csv_optional_milliseconds(report.p50),
            csv_optional_milliseconds(report.p95),
            csv_optional_milliseconds(report.p99),
            report.logical_application_bytes.to_string(),
            report.line_one_udp_payload_bytes.to_string(),
            report.line_two_udp_payload_bytes.to_string(),
            report.total_udp_payload_bytes().to_string(),
            format!("{:.6}", report.udp_wire_ratio()),
            report.line_one_client_packets.to_string(),
            report.line_two_client_packets.to_string(),
            true.to_string(),
            false.to_string(),
            report.processes_alive_at_end.to_string(),
            report.measurement_is_complete().to_string(),
            report.used_only_target_line().to_string(),
            report.smoke_safety_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_hysteria_failover_csv(
    path: &str,
    observations: &[HysteriaFailoverObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "direction,round,line_one_seed,line_two_seed,hysteria_version,hysteria_sha256,congestion,total_duration_ms,failure_after_ms,original_connection_reused,recovered_after_failure,data_intact,exchange_complete,continuity_pass,recovery_gap_ms,records_received,records_before_failure,records_after_failure,application_bytes_received,protocol_error,failure_reason,application_connection_open_at_deadline,measurement_timed_out,client_line_one_udp_payload_bytes_after_failure,client_line_two_udp_payload_bytes_after_failure,server_line_one_udp_payload_bytes_after_failure,server_line_two_udp_payload_bytes_after_failure,target_line_udp_payload_bytes_after_failure,non_target_line_udp_payload_bytes_after_failure,client_line_one_packets_after_failure,client_line_two_packets_after_failure,server_line_one_packets_after_failure,server_line_two_packets_after_failure,tls_exact_validation,obfs_enabled,processes_alive_at_end,infrastructure_pass\n",
    );

    for observation in observations {
        let report = &observation.report;
        let protocol_error = report
            .protocol_error
            .as_deref()
            .unwrap_or_default()
            .replace([',', '\n', '\r'], ";");
        let failure_reason = report
            .failure_reason
            .as_deref()
            .unwrap_or_default()
            .replace([',', '\n', '\r'], ";");
        let fields = vec![
            observation.direction.description().to_owned(),
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            "2.9.3".to_owned(),
            "66dbdb0608f25f3057b433afe975a9fc1af2ca8e512479e294988b3ef363d6c1".to_owned(),
            report.congestion.description().to_owned(),
            format!("{:.3}", milliseconds(report.total_duration)),
            format!("{:.3}", milliseconds(report.failure_after)),
            report.original_connection_reused.to_string(),
            report.recovered_after_failure.to_string(),
            report.data_intact.to_string(),
            report.exchange_complete.to_string(),
            report.continuity_pass.to_string(),
            csv_optional_milliseconds(report.recovery_gap),
            report.records_received.to_string(),
            report.records_before_failure.to_string(),
            report.records_after_failure.to_string(),
            report.application_bytes_received.to_string(),
            protocol_error,
            failure_reason,
            report.application_connection_open_at_deadline.to_string(),
            report.measurement_timed_out.to_string(),
            report
                .client_line_one_udp_payload_bytes_after_failure
                .to_string(),
            report
                .client_line_two_udp_payload_bytes_after_failure
                .to_string(),
            report
                .server_line_one_udp_payload_bytes_after_failure
                .to_string(),
            report
                .server_line_two_udp_payload_bytes_after_failure
                .to_string(),
            report
                .target_line_udp_payload_bytes_after_failure()
                .to_string(),
            report
                .non_target_line_udp_payload_bytes_after_failure()
                .to_string(),
            report.client_line_one_packets_after_failure.to_string(),
            report.client_line_two_packets_after_failure.to_string(),
            report.server_line_one_packets_after_failure.to_string(),
            report.server_line_two_packets_after_failure.to_string(),
            true.to_string(),
            false.to_string(),
            report.processes_alive_at_end.to_string(),
            report.infrastructure_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_recovery_screening_csv(
    path: &str,
    observations: &[RecoveryScreeningObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,recovery,recovered,recovery_ms,completion_ms,failure_reason,primary_path_open,secondary_path_open,failover_primary_udp_bytes,failover_secondary_udp_bytes,failover_total_udp_bytes,primary_lost_packets,secondary_lost_packets,failover_pto_hedges,failover_pto_hedge_bytes,normal_throughput_mbps,normal_total_udp_bytes,normal_all_paths_open,normal_pto_hedges,normal_pto_hedge_bytes,high_loss_throughput_mbps,high_loss_total_udp_bytes,high_loss_any_path_open,high_loss_pto_hedges,high_loss_pto_hedge_bytes\n",
    );

    for observation in observations {
        let failover_total_udp = observation
            .failover
            .primary_bytes_after_blackhole
            .saturating_add(observation.failover.secondary_bytes_after_blackhole);
        let failover_hedges = observation
            .failover
            .primary_pto_hedges
            .saturating_add(observation.failover.secondary_pto_hedges);
        let failover_hedge_bytes = observation
            .failover
            .primary_pto_hedge_bytes
            .saturating_add(observation.failover.secondary_pto_hedge_bytes);
        let recovery_ms = observation
            .failover
            .recovery_time
            .map(milliseconds)
            .map(|value| format!("{value:.3}"))
            .unwrap_or_default();
        let completion_ms = observation
            .failover
            .completion_time
            .map(milliseconds)
            .map(|value| format!("{value:.3}"))
            .unwrap_or_default();
        let failure_reason = observation
            .failover
            .failure_reason
            .as_deref()
            .unwrap_or_default()
            .replace(',', ";")
            .replace(['\n', '\r'], " ");

        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{},{},{},{},{:.6},{},{},{},{}",
            observation.round,
            observation.seeds.line_one,
            observation.seeds.line_two,
            observation.pto_recovery.description(),
            observation.failover.recovered,
            recovery_ms,
            completion_ms,
            failure_reason,
            observation.failover.primary_path_open,
            observation.failover.secondary_path_open,
            observation.failover.primary_bytes_after_blackhole,
            observation.failover.secondary_bytes_after_blackhole,
            failover_total_udp,
            observation.failover.primary_lost_packets,
            observation.failover.secondary_lost_packets,
            failover_hedges,
            failover_hedge_bytes,
            observation.normal.throughput_mbps,
            observation.normal.total_udp_bytes_sent,
            observation.normal.all_configured_paths_open,
            total_pto_hedges(&observation.normal),
            total_pto_hedge_bytes(&observation.normal),
            observation.high_loss.throughput_mbps,
            observation.high_loss.total_udp_bytes_sent,
            observation.high_loss.any_configured_path_open,
            total_pto_hedges(&observation.high_loss),
            total_pto_hedge_bytes(&observation.high_loss),
        )?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_formal_failover_csv(
    path: &str,
    observations: &[FormalFailoverObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "direction,round,line_one_seed,line_two_seed,recovery,recovered,data_intact,exchange_complete,recovery_gap_ms,transfer_duration_ms,records_received,application_bytes_received,failure_reason,primary_fresh_bytes_before_blackhole,secondary_fresh_bytes_before_blackhole,primary_pto_hedges_before_blackhole,secondary_pto_hedges_before_blackhole,primary_pto_hedge_bytes_before_blackhole,secondary_pto_hedge_bytes_before_blackhole,primary_udp_bytes_after_blackhole,secondary_udp_bytes_after_blackhole,total_udp_bytes_after_blackhole,primary_lost_packets,secondary_lost_packets,pto_hedges_after_blackhole,pto_hedge_bytes_after_blackhole,primary_path_open,secondary_path_open,primary_loss_timeouts_after_blackhole,secondary_loss_timeouts_after_blackhole,primary_pto_timeouts_after_blackhole,secondary_pto_timeouts_after_blackhole,primary_pto_recovery_attempts_after_blackhole,primary_pto_recovery_empty_attempts_after_blackhole,primary_last_pto_unacked_bytes,primary_last_pto_stream_frames,secondary_pto_recovery_attempts_after_blackhole,secondary_pto_recovery_empty_attempts_after_blackhole,secondary_last_pto_unacked_bytes,secondary_last_pto_stream_frames,primary_final_cwnd,secondary_final_cwnd,receiver_primary_path_acks_same_path_after_blackhole,receiver_primary_path_acks_cross_path_after_blackhole,receiver_secondary_path_acks_same_path_after_blackhole,receiver_secondary_path_acks_cross_path_after_blackhole,primary_open_at_fault,secondary_open_at_fault,first_primary_loss_timeout_ms,first_primary_pto_ms,first_primary_recovery_attempt_ms,first_primary_hedge_ms,first_secondary_udp_send_ms,first_receiver_primary_cross_path_ack_ms,first_receiver_secondary_same_path_ack_ms,primary_closed_ms,secondary_closed_ms,recovery_gap_started_after_fault_ms,recovery_gap_ended_after_fault_ms,recovery_gap_next_sequence,primary_rtt_at_fault_ms,primary_pto_at_fault_ms,primary_cwnd_at_fault,primary_bytes_in_flight_at_fault,primary_ack_eliciting_in_flight_at_fault,primary_tracked_sent_packets_at_fault,primary_tracked_ack_eliciting_packets_at_fault,primary_latest_ack_eliciting_pn_at_fault,primary_pto_count_at_fault,primary_loss_timer_armed_at_fault,primary_ack_eliciting_pn_advance_after_fault,first_primary_ack_eliciting_send_ms,last_primary_ack_eliciting_send_ms,first_primary_udp_receive_ms,last_primary_udp_receive_ms,first_primary_loss_timer_unarmed_ms,first_primary_ack_eliciting_in_flight_zero_ms,first_primary_tracked_ack_eliciting_zero_ms,max_primary_bytes_in_flight_after_fault,max_primary_ack_eliciting_in_flight_after_fault,max_primary_tracked_sent_packets_after_fault,max_primary_tracked_ack_eliciting_after_fault,primary_final_rtt_ms,primary_final_pto_ms,primary_final_bytes_in_flight,primary_final_ack_eliciting_in_flight,primary_final_tracked_sent_packets,primary_final_tracked_ack_eliciting_packets,primary_final_loss_timer_armed,primary_abandon_recovery_attempts_after_blackhole,primary_abandon_recovery_empty_attempts_after_blackhole,primary_abandon_reinjections_after_blackhole,primary_abandon_reinjected_bytes_after_blackhole,secondary_abandon_recovery_attempts_after_blackhole,secondary_abandon_recovery_empty_attempts_after_blackhole,secondary_abandon_reinjections_after_blackhole,secondary_abandon_reinjected_bytes_after_blackhole,primary_ack_progress_recovery_timeouts_after_blackhole,primary_ack_progress_recovery_attempts_after_blackhole,primary_ack_progress_recovery_empty_attempts_after_blackhole,primary_ack_progress_reinjections_after_blackhole,primary_ack_progress_reinjected_bytes_after_blackhole,primary_ack_progress_feedback_probe_timeouts_after_blackhole,primary_ack_progress_feedback_probes_after_blackhole,primary_ack_progress_feedback_probe_bytes_after_blackhole,secondary_ack_progress_recovery_timeouts_after_blackhole,secondary_ack_progress_recovery_attempts_after_blackhole,secondary_ack_progress_recovery_empty_attempts_after_blackhole,secondary_ack_progress_reinjections_after_blackhole,secondary_ack_progress_reinjected_bytes_after_blackhole,secondary_ack_progress_feedback_probe_timeouts_after_blackhole,secondary_ack_progress_feedback_probes_after_blackhole,secondary_ack_progress_feedback_probe_bytes_after_blackhole,first_primary_ack_progress_timeout_ms,first_primary_ack_progress_reinjection_ms,first_primary_ack_progress_feedback_probe_ms,primary_final_ack_progress_timer_armed,first_secondary_stream_retransmit_ms,first_secondary_fresh_stream_ms,first_receiver_secondary_cross_path_ack_ms,primary_path_ack_escape_requests_after_blackhole,secondary_path_ack_escape_requests_after_blackhole,receiver_primary_path_ack_escape_acks_after_blackhole,receiver_secondary_path_ack_escape_acks_after_blackhole,primary_stream_gap_rescue_probes_after_blackhole,primary_stream_gap_rescue_bytes_after_blackhole,secondary_stream_gap_rescue_probes_after_blackhole,secondary_stream_gap_rescue_bytes_after_blackhole,receiver_primary_blocked_credit_handoffs_after_blackhole,receiver_primary_blocked_credit_max_data_requeues_after_blackhole,receiver_primary_blocked_credit_max_stream_data_requeues_after_blackhole,receiver_secondary_blocked_credit_handoffs_after_blackhole,receiver_secondary_blocked_credit_max_data_requeues_after_blackhole,receiver_secondary_blocked_credit_max_stream_data_requeues_after_blackhole,sender_primary_stream_progress_updates_after_blackhole,sender_primary_stream_progress_acked_bytes_after_blackhole,sender_secondary_stream_progress_updates_after_blackhole,sender_secondary_stream_progress_acked_bytes_after_blackhole,receiver_primary_stream_progress_updates_after_blackhole,receiver_primary_stream_progress_acked_bytes_after_blackhole,receiver_secondary_stream_progress_updates_after_blackhole,receiver_secondary_stream_progress_acked_bytes_after_blackhole\n",
    );

    for observation in observations {
        let failure_reason = observation
            .report
            .failure_reason
            .as_deref()
            .unwrap_or_default()
            .replace(',', ";")
            .replace(['\n', '\r'], " ");
        let recovery_gap_ms = observation
            .report
            .recovery_gap
            .map(milliseconds)
            .map(|value| format!("{value:.3}"))
            .unwrap_or_default();
        let transfer_duration_ms = observation
            .report
            .transfer_duration
            .map(milliseconds)
            .map(|value| format!("{value:.3}"))
            .unwrap_or_default();
        let before_primary = &observation.report.sender_primary_before_blackhole;
        let before_secondary = &observation.report.sender_secondary_before_blackhole;
        let after_primary = &observation.report.sender_primary_after_blackhole;
        let after_secondary = &observation.report.sender_secondary_after_blackhole;
        let receiver_primary = &observation.report.receiver_primary_after_blackhole;
        let receiver_secondary = &observation.report.receiver_secondary_after_blackhole;
        let total_udp = formal_failover_udp_bytes(&observation.report);
        let total_hedges = after_primary
            .pto_hedges
            .saturating_add(after_secondary.pto_hedges);
        let total_hedge_bytes = after_primary
            .pto_hedge_bytes
            .saturating_add(after_secondary.pto_hedge_bytes);

        write!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            observation.direction.description(),
            observation.round,
            observation.seeds.line_one,
            observation.seeds.line_two,
            observation.pto_recovery.description(),
            observation.report.recovered,
            observation.report.data_intact,
            observation.report.exchange_complete,
            recovery_gap_ms,
            transfer_duration_ms,
            observation.report.records_received,
            observation.report.application_bytes_received,
            failure_reason,
            before_primary.fresh_stream_bytes_sent,
            before_secondary.fresh_stream_bytes_sent,
            before_primary.pto_hedges,
            before_secondary.pto_hedges,
            before_primary.pto_hedge_bytes,
            before_secondary.pto_hedge_bytes,
            after_primary.udp_bytes_sent,
            after_secondary.udp_bytes_sent,
            total_udp,
            after_primary.lost_packets,
            after_secondary.lost_packets,
            total_hedges,
            total_hedge_bytes,
            observation.report.primary_path_open,
            observation.report.secondary_path_open,
        )?;
        write!(
            csv,
            ",{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            after_primary.loss_detection_timeouts,
            after_secondary.loss_detection_timeouts,
            after_primary.pto_timeouts,
            after_secondary.pto_timeouts,
            after_primary.pto_recovery_attempts,
            after_primary.pto_recovery_empty_attempts,
            after_primary.last_pto_recovery_unacked_bytes,
            after_primary.last_pto_recovery_stream_frames,
            after_secondary.pto_recovery_attempts,
            after_secondary.pto_recovery_empty_attempts,
            after_secondary.last_pto_recovery_unacked_bytes,
            after_secondary.last_pto_recovery_stream_frames,
            after_primary.final_cwnd,
            after_secondary.final_cwnd,
            receiver_primary.path_acks_same_path,
            receiver_primary.path_acks_cross_path,
            receiver_secondary.path_acks_same_path,
            receiver_secondary.path_acks_cross_path,
        )?;
        write!(
            csv,
            ",{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            observation.report.timeline.primary_open_at_fault,
            observation.report.timeline.secondary_open_at_fault,
            csv_optional_milliseconds(observation.report.timeline.first_primary_loss_timeout),
            csv_optional_milliseconds(observation.report.timeline.first_primary_pto),
            csv_optional_milliseconds(observation.report.timeline.first_primary_recovery_attempt,),
            csv_optional_milliseconds(observation.report.timeline.first_primary_hedge),
            csv_optional_milliseconds(observation.report.timeline.first_secondary_udp_send),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_receiver_primary_cross_path_ack,
            ),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_receiver_secondary_same_path_ack,
            ),
            csv_optional_milliseconds(observation.report.timeline.primary_closed),
            csv_optional_milliseconds(observation.report.timeline.secondary_closed),
            csv_optional_milliseconds(observation.report.recovery_gap_started_after_fault),
            csv_optional_milliseconds(observation.report.recovery_gap_ended_after_fault),
            observation
                .report
                .recovery_gap_next_sequence
                .map_or_else(String::new, |sequence| sequence.to_string()),
        )?;
        write!(
            csv,
            ",{:.3},{:.3},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.3},{:.3},{},{},{},{},{}",
            milliseconds(observation.report.timeline.primary_rtt_at_fault),
            milliseconds(observation.report.timeline.primary_pto_at_fault),
            observation.report.timeline.primary_cwnd_at_fault,
            observation.report.timeline.primary_bytes_in_flight_at_fault,
            observation
                .report
                .timeline
                .primary_ack_eliciting_packets_in_flight_at_fault,
            observation
                .report
                .timeline
                .primary_tracked_sent_packets_at_fault,
            observation
                .report
                .timeline
                .primary_tracked_ack_eliciting_packets_at_fault,
            observation
                .report
                .timeline
                .primary_latest_ack_eliciting_packet_number_at_fault,
            observation.report.timeline.primary_pto_count_at_fault,
            observation
                .report
                .timeline
                .primary_loss_detection_timer_armed_at_fault,
            after_primary.ack_eliciting_packet_number_advance,
            csv_optional_milliseconds(observation.report.timeline.first_primary_ack_eliciting_send,),
            csv_optional_milliseconds(observation.report.timeline.last_primary_ack_eliciting_send,),
            csv_optional_milliseconds(observation.report.timeline.first_primary_udp_receive),
            csv_optional_milliseconds(observation.report.timeline.last_primary_udp_receive),
            csv_optional_milliseconds(observation.report.timeline.first_primary_loss_timer_unarmed,),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_primary_ack_eliciting_in_flight_zero,
            ),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_primary_tracked_ack_eliciting_zero,
            ),
            observation.report.timeline.max_primary_bytes_in_flight,
            observation
                .report
                .timeline
                .max_primary_ack_eliciting_packets_in_flight,
            observation.report.timeline.max_primary_tracked_sent_packets,
            observation
                .report
                .timeline
                .max_primary_tracked_ack_eliciting_packets,
            milliseconds(after_primary.final_rtt),
            milliseconds(after_primary.final_pto),
            after_primary.final_bytes_in_flight,
            after_primary.final_ack_eliciting_packets_in_flight,
            after_primary.final_tracked_sent_packets,
            after_primary.final_tracked_ack_eliciting_packets,
            after_primary.final_loss_detection_timer_armed,
        )?;
        write!(
            csv,
            ",{},{},{},{},{},{},{},{}",
            after_primary.path_abandon_recovery_attempts,
            after_primary.path_abandon_recovery_empty_attempts,
            after_primary.path_abandon_reinjections,
            after_primary.path_abandon_reinjected_bytes,
            after_secondary.path_abandon_recovery_attempts,
            after_secondary.path_abandon_recovery_empty_attempts,
            after_secondary.path_abandon_reinjections,
            after_secondary.path_abandon_reinjected_bytes,
        )?;
        write!(
            csv,
            ",{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            after_primary.ack_progress_recovery_timeouts,
            after_primary.ack_progress_recovery_attempts,
            after_primary.ack_progress_recovery_empty_attempts,
            after_primary.ack_progress_reinjections,
            after_primary.ack_progress_reinjected_bytes,
            after_primary.ack_progress_feedback_probe_timeouts,
            after_primary.ack_progress_feedback_probes,
            after_primary.ack_progress_feedback_probe_bytes,
            after_secondary.ack_progress_recovery_timeouts,
            after_secondary.ack_progress_recovery_attempts,
            after_secondary.ack_progress_recovery_empty_attempts,
            after_secondary.ack_progress_reinjections,
            after_secondary.ack_progress_reinjected_bytes,
            after_secondary.ack_progress_feedback_probe_timeouts,
            after_secondary.ack_progress_feedback_probes,
            after_secondary.ack_progress_feedback_probe_bytes,
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_primary_ack_progress_timeout,
            ),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_primary_ack_progress_reinjection,
            ),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_primary_ack_progress_feedback_probe,
            ),
            after_primary.final_ack_progress_recovery_timer_armed,
        )?;
        write!(
            csv,
            ",{},{},{}",
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_secondary_stream_retransmit,
            ),
            csv_optional_milliseconds(observation.report.timeline.first_secondary_fresh_stream,),
            csv_optional_milliseconds(
                observation
                    .report
                    .timeline
                    .first_receiver_secondary_cross_path_ack,
            ),
        )?;
        write!(
            csv,
            ",{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            after_primary.path_ack_escape_requests,
            after_secondary.path_ack_escape_requests,
            receiver_primary.path_ack_escape_acks,
            receiver_secondary.path_ack_escape_acks,
            after_primary.stream_gap_rescue_probes,
            after_primary.stream_gap_rescue_bytes,
            after_secondary.stream_gap_rescue_probes,
            after_secondary.stream_gap_rescue_bytes,
            receiver_primary.blocked_credit_handoffs,
            receiver_primary.blocked_credit_max_data_requeues,
            receiver_primary.blocked_credit_max_stream_data_requeues,
            receiver_secondary.blocked_credit_handoffs,
            receiver_secondary.blocked_credit_max_data_requeues,
            receiver_secondary.blocked_credit_max_stream_data_requeues,
        )?;
        writeln!(
            csv,
            ",{},{},{},{},{},{},{},{}",
            after_primary.stream_progress_updates,
            after_primary.stream_progress_acked_bytes,
            after_secondary.stream_progress_updates,
            after_secondary.stream_progress_acked_bytes,
            receiver_primary.stream_progress_updates,
            receiver_primary.stream_progress_acked_bytes,
            receiver_secondary.stream_progress_updates,
            receiver_secondary.stream_progress_acked_bytes,
        )?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_stream_state_csv(path: &str, observations: &[FormalFailoverObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "direction,round,line_one_seed,line_two_seed,elapsed_after_fault_ms,stream_id,sender_fully_acked_offset,sender_unacknowledged_bytes,sender_lowest_retransmit_offset,sender_retransmit_bytes,sender_offset,sender_max_stream_data,sender_stream_flow_control_blocked,sender_connection_flow_control_blocked,sender_connection_data,sender_max_data,sender_max_data_blocked,receiver_contiguous_offset,receiver_highest_offset,receiver_buffered_after_gap_bytes,feedback_debt_bytes,retransmit_target_minus_receiver_bytes,receiver_sent_max_stream_data,receiver_current_max_stream_data,receiver_max_stream_data_pending,receiver_max_stream_data_in_flight_packets,receiver_data,receiver_max_data,receiver_sent_max_data,receiver_max_data_pending,receiver_max_data_in_flight_packets,response_sender_fully_acked_offset,response_sender_unacknowledged_bytes,response_sender_lowest_retransmit_offset,response_sender_retransmit_bytes,response_sender_offset,response_sender_max_stream_data,response_sender_flow_control_blocked,response_sender_connection_blocked,response_receiver_contiguous_offset,response_receiver_highest_offset,primary_ack_progress_obligation_stream_id,primary_ack_progress_obligation_offset,primary_ack_progress_obligation_age_ms,primary_ack_progress_deadline_remaining_ms,primary_ack_progress_full_recovery_deadline_remaining_ms,primary_ack_progress_service_deadline_ms,primary_ack_progress_alternative_recovery_budget_ms,primary_ack_progress_feedback_probe_staged,primary_ack_progress_timer_armed,primary_ack_progress_stream_frames_in_flight,primary_ack_progress_has_cross_path_alternative,primary_ack_progress_pto_recovery_probe_active,primary_authenticated_feedback_age_ms,secondary_authenticated_feedback_age_ms,primary_stream_progress_updates,primary_stream_progress_acked_bytes,secondary_stream_progress_updates,secondary_stream_progress_acked_bytes,secondary_ack_progress_has_cross_path_alternative,secondary_lost_packets,secondary_stream_retransmit_bytes,secondary_pto_timeouts,secondary_rtt_ms,secondary_pto_ms,secondary_cwnd,secondary_bytes_in_flight,secondary_ack_eliciting_in_flight,secondary_tracked_sent_packets,secondary_tracked_ack_eliciting_packets,secondary_latest_ack_eliciting_pn,secondary_pto_count,secondary_loss_timer_armed,receiver_primary_tracked_max_data_packets,receiver_primary_tracked_max_stream_data_packets,receiver_primary_pto_count,receiver_primary_loss_timer_armed,receiver_primary_stream_fresh_bytes,receiver_secondary_tracked_max_data_packets,receiver_secondary_tracked_max_stream_data_packets,receiver_secondary_pto_count,receiver_secondary_loss_timer_armed,receiver_secondary_stream_fresh_bytes,receiver_secondary_stream_retransmit_bytes,receiver_secondary_lost_packets,receiver_secondary_pto_timeouts,receiver_secondary_bytes_in_flight,receiver_secondary_ack_eliciting_in_flight,receiver_secondary_tracked_sent_packets,receiver_secondary_tracked_ack_eliciting_packets,secondary_stream_gap_rescue_probes,secondary_stream_gap_rescue_bytes\n",
    );

    for observation in observations {
        for sample in &observation.report.stream_state_samples {
            let buffered_after_gap = match (
                sample.receiver_highest_offset,
                sample.receiver_contiguous_offset,
            ) {
                (Some(highest), Some(contiguous)) => Some(highest.saturating_sub(contiguous)),
                _ => None,
            };
            let feedback_debt = match (
                sample.receiver_contiguous_offset,
                sample.sender_fully_acked_offset,
            ) {
                (Some(contiguous), Some(acked)) => Some(contiguous.saturating_sub(acked)),
                _ => None,
            };
            let retransmit_target_delta = match (
                sample.sender_lowest_retransmit_offset,
                sample.receiver_contiguous_offset,
            ) {
                (Some(target), Some(contiguous)) => {
                    Some(i128::from(target) - i128::from(contiguous))
                }
                _ => None,
            };

            let fields = vec![
                observation.direction.description().to_owned(),
                observation.round.to_string(),
                observation.seeds.line_one.to_string(),
                observation.seeds.line_two.to_string(),
                format!("{:.3}", milliseconds(sample.elapsed_after_fault)),
                u64::from(sample.stream_id).to_string(),
                csv_optional_u64(sample.sender_fully_acked_offset),
                csv_optional_u64(sample.sender_unacknowledged_bytes),
                csv_optional_u64(sample.sender_lowest_retransmit_offset),
                csv_optional_u64(sample.sender_retransmit_bytes),
                csv_optional_u64(sample.sender_offset),
                csv_optional_u64(sample.sender_max_stream_data),
                csv_optional_bool(sample.sender_stream_flow_control_blocked),
                csv_optional_bool(sample.sender_connection_flow_control_blocked),
                sample.sender_connection_data.to_string(),
                sample.sender_max_data.to_string(),
                sample.sender_max_data_blocked.to_string(),
                csv_optional_u64(sample.receiver_contiguous_offset),
                csv_optional_u64(sample.receiver_highest_offset),
                csv_optional_u64(buffered_after_gap),
                csv_optional_u64(feedback_debt),
                retransmit_target_delta
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                csv_optional_u64(sample.receiver_sent_max_stream_data),
                csv_optional_u64(sample.receiver_current_max_stream_data),
                sample.receiver_max_stream_data_pending.to_string(),
                sample
                    .receiver_max_stream_data_in_flight_packets
                    .to_string(),
                sample.receiver_data.to_string(),
                sample.receiver_max_data.to_string(),
                sample.receiver_sent_max_data.to_string(),
                sample.receiver_max_data_pending.to_string(),
                sample.receiver_max_data_in_flight_packets.to_string(),
                csv_optional_u64(sample.response_sender_fully_acked_offset),
                csv_optional_u64(sample.response_sender_unacknowledged_bytes),
                csv_optional_u64(sample.response_sender_lowest_retransmit_offset),
                csv_optional_u64(sample.response_sender_retransmit_bytes),
                csv_optional_u64(sample.response_sender_offset),
                csv_optional_u64(sample.response_sender_max_stream_data),
                csv_optional_bool(sample.response_sender_flow_control_blocked),
                csv_optional_bool(sample.response_sender_connection_blocked),
                csv_optional_u64(sample.response_receiver_contiguous_offset),
                csv_optional_u64(sample.response_receiver_highest_offset),
                sample
                    .primary_ack_progress_obligation_stream_id
                    .map(|id| u64::from(id).to_string())
                    .unwrap_or_default(),
                csv_optional_u64(sample.primary_ack_progress_obligation_offset),
                sample
                    .primary_ack_progress_obligation_age
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample
                    .primary_ack_progress_deadline_remaining
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample
                    .primary_ack_progress_full_recovery_deadline_remaining
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample
                    .primary_ack_progress_service_deadline
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample
                    .primary_ack_progress_alternative_recovery_budget
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample
                    .primary_ack_progress_feedback_probe_staged
                    .to_string(),
                sample.primary_ack_progress_timer_armed.to_string(),
                sample
                    .primary_ack_progress_stream_frames_in_flight
                    .to_string(),
                sample
                    .primary_ack_progress_has_cross_path_alternative
                    .to_string(),
                sample
                    .primary_ack_progress_pto_recovery_probe_active
                    .to_string(),
                sample
                    .primary_authenticated_feedback_age
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample
                    .secondary_authenticated_feedback_age
                    .map(|duration| format!("{:.3}", milliseconds(duration)))
                    .unwrap_or_default(),
                sample.primary_stream_progress_updates.to_string(),
                sample.primary_stream_progress_acked_bytes.to_string(),
                sample.secondary_stream_progress_updates.to_string(),
                sample.secondary_stream_progress_acked_bytes.to_string(),
                sample
                    .secondary_ack_progress_has_cross_path_alternative
                    .to_string(),
                sample.secondary_lost_packets.to_string(),
                sample.secondary_stream_retransmit_bytes.to_string(),
                sample.secondary_pto_timeouts.to_string(),
                format!("{:.3}", milliseconds(sample.secondary_rtt)),
                format!("{:.3}", milliseconds(sample.secondary_pto)),
                sample.secondary_cwnd.to_string(),
                sample.secondary_bytes_in_flight.to_string(),
                sample.secondary_ack_eliciting_packets_in_flight.to_string(),
                sample.secondary_tracked_sent_packets.to_string(),
                sample.secondary_tracked_ack_eliciting_packets.to_string(),
                sample
                    .secondary_latest_ack_eliciting_packet_number
                    .to_string(),
                sample.secondary_pto_count.to_string(),
                sample.secondary_loss_detection_timer_armed.to_string(),
                sample.receiver_primary_tracked_max_data_packets.to_string(),
                sample
                    .receiver_primary_tracked_max_stream_data_packets
                    .to_string(),
                sample.receiver_primary_pto_count.to_string(),
                sample
                    .receiver_primary_loss_detection_timer_armed
                    .to_string(),
                sample.receiver_primary_stream_fresh_bytes.to_string(),
                sample
                    .receiver_secondary_tracked_max_data_packets
                    .to_string(),
                sample
                    .receiver_secondary_tracked_max_stream_data_packets
                    .to_string(),
                sample.receiver_secondary_pto_count.to_string(),
                sample
                    .receiver_secondary_loss_detection_timer_armed
                    .to_string(),
                sample.receiver_secondary_stream_fresh_bytes.to_string(),
                sample
                    .receiver_secondary_stream_retransmit_bytes
                    .to_string(),
                sample.receiver_secondary_lost_packets.to_string(),
                sample.receiver_secondary_pto_timeouts.to_string(),
                sample.receiver_secondary_bytes_in_flight.to_string(),
                sample
                    .receiver_secondary_ack_eliciting_packets_in_flight
                    .to_string(),
                sample.receiver_secondary_tracked_sent_packets.to_string(),
                sample
                    .receiver_secondary_tracked_ack_eliciting_packets
                    .to_string(),
                sample.secondary_stream_gap_rescue_probes.to_string(),
                sample.secondary_stream_gap_rescue_bytes.to_string(),
            ];
            writeln!(csv, "{}", fields.join(","))?;
        }
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn optional_milliseconds(duration: Option<Duration>) -> String {
    duration
        .map(|value| format!("{:.2} ms", milliseconds(value)))
        .unwrap_or_else(|| "无有效样本".to_owned())
}

fn csv_optional_milliseconds(duration: Option<Duration>) -> String {
    duration
        .map(milliseconds)
        .map(|value| format!("{value:.3}"))
        .unwrap_or_default()
}

fn csv_optional_u64(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn csv_optional_bool(value: Option<bool>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn yes_or_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}

fn lab_error(message: impl Into<String>) -> flowweave_lab::LabError {
    io::Error::other(message.into()).into()
}
