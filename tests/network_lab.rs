use std::{env, fmt::Write as _, fs, io, process::Command, time::Duration};

use flowweave_lab::{
    DatagramMeasurement, FailoverDirection, FailoverReport, LabResult, MultipathScheduler,
    NetworkBenchmarkConfig, NetworkBenchmarkReport, PathMode, PtoRecovery,
    SustainedBenchmarkConfig, SustainedFailoverConfig, SustainedFailoverReport,
    run_blackhole_failover, run_network_benchmark, run_sustained_blackhole_failover,
    run_sustained_network_benchmark,
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
#[ignore = "必须通过 scripts/run_netem_lab.sh formal-gap-watch 在隔离网络命名空间中运行"]
async fn failover_feedback_gap_watch_formal_bidirectional_lab() -> LabResult<()> {
    const RESULT_PATH: &str =
        "benchmark-results/2026-07-12-feedback-gap-watch-formal-v5-summary.csv";
    const TIMELINE_PATH: &str =
        "benchmark-results/2026-07-12-feedback-gap-watch-formal-v5-timeline.csv";
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
    ensure_isolated_network_namespace()?;

    const REPETITIONS: usize = 10;
    const SEED_INDEX: usize = 3;
    let direction = FailoverDirection::ClientToServer;
    let seeds = SEED_PAIRS[SEED_INDEX];
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");
    let application_seed = 151_u8.wrapping_add((SEED_INDEX + 1) as u8);

    println!();
    println!("{title}");
    println!("固定线路种子、业务种子、方向和算法，完整保留 {REPETITIONS} 次结果；不挑样本。");

    let mut observations = Vec::with_capacity(REPETITIONS);
    write_formal_failover_csv(result_path, &observations)?;
    write_stream_state_csv(timeline_path, &observations)?;

    for repetition in 1..=REPETITIONS {
        println!();
        println!(
            "稳定性重复 {repetition}/{REPETITIONS}：线路一种子 {}，线路二种子 {}",
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

fn screening_order(round_index: usize) -> Vec<ScreeningParticipant> {
    let mut order = ScreeningParticipant::ALL.to_vec();
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
        "  关键缺口探针：主路探针/触发字节 {}/{}；备用路 {}/{}",
        after_primary.stream_gap_rescue_probes,
        after_primary.stream_gap_rescue_bytes,
        after_secondary.stream_gap_rescue_probes,
        after_secondary.stream_gap_rescue_bytes,
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
        "direction,round,line_one_seed,line_two_seed,recovery,recovered,data_intact,exchange_complete,recovery_gap_ms,transfer_duration_ms,records_received,application_bytes_received,failure_reason,primary_fresh_bytes_before_blackhole,secondary_fresh_bytes_before_blackhole,primary_pto_hedges_before_blackhole,secondary_pto_hedges_before_blackhole,primary_pto_hedge_bytes_before_blackhole,secondary_pto_hedge_bytes_before_blackhole,primary_udp_bytes_after_blackhole,secondary_udp_bytes_after_blackhole,total_udp_bytes_after_blackhole,primary_lost_packets,secondary_lost_packets,pto_hedges_after_blackhole,pto_hedge_bytes_after_blackhole,primary_path_open,secondary_path_open,primary_loss_timeouts_after_blackhole,secondary_loss_timeouts_after_blackhole,primary_pto_timeouts_after_blackhole,secondary_pto_timeouts_after_blackhole,primary_pto_recovery_attempts_after_blackhole,primary_pto_recovery_empty_attempts_after_blackhole,primary_last_pto_unacked_bytes,primary_last_pto_stream_frames,secondary_pto_recovery_attempts_after_blackhole,secondary_pto_recovery_empty_attempts_after_blackhole,secondary_last_pto_unacked_bytes,secondary_last_pto_stream_frames,primary_final_cwnd,secondary_final_cwnd,receiver_primary_path_acks_same_path_after_blackhole,receiver_primary_path_acks_cross_path_after_blackhole,receiver_secondary_path_acks_same_path_after_blackhole,receiver_secondary_path_acks_cross_path_after_blackhole,primary_open_at_fault,secondary_open_at_fault,first_primary_loss_timeout_ms,first_primary_pto_ms,first_primary_recovery_attempt_ms,first_primary_hedge_ms,first_secondary_udp_send_ms,first_receiver_primary_cross_path_ack_ms,first_receiver_secondary_same_path_ack_ms,primary_closed_ms,secondary_closed_ms,recovery_gap_started_after_fault_ms,recovery_gap_ended_after_fault_ms,recovery_gap_next_sequence,primary_rtt_at_fault_ms,primary_pto_at_fault_ms,primary_cwnd_at_fault,primary_bytes_in_flight_at_fault,primary_ack_eliciting_in_flight_at_fault,primary_tracked_sent_packets_at_fault,primary_tracked_ack_eliciting_packets_at_fault,primary_latest_ack_eliciting_pn_at_fault,primary_pto_count_at_fault,primary_loss_timer_armed_at_fault,primary_ack_eliciting_pn_advance_after_fault,first_primary_ack_eliciting_send_ms,last_primary_ack_eliciting_send_ms,first_primary_udp_receive_ms,last_primary_udp_receive_ms,first_primary_loss_timer_unarmed_ms,first_primary_ack_eliciting_in_flight_zero_ms,first_primary_tracked_ack_eliciting_zero_ms,max_primary_bytes_in_flight_after_fault,max_primary_ack_eliciting_in_flight_after_fault,max_primary_tracked_sent_packets_after_fault,max_primary_tracked_ack_eliciting_after_fault,primary_final_rtt_ms,primary_final_pto_ms,primary_final_bytes_in_flight,primary_final_ack_eliciting_in_flight,primary_final_tracked_sent_packets,primary_final_tracked_ack_eliciting_packets,primary_final_loss_timer_armed,primary_abandon_recovery_attempts_after_blackhole,primary_abandon_recovery_empty_attempts_after_blackhole,primary_abandon_reinjections_after_blackhole,primary_abandon_reinjected_bytes_after_blackhole,secondary_abandon_recovery_attempts_after_blackhole,secondary_abandon_recovery_empty_attempts_after_blackhole,secondary_abandon_reinjections_after_blackhole,secondary_abandon_reinjected_bytes_after_blackhole,primary_ack_progress_recovery_timeouts_after_blackhole,primary_ack_progress_recovery_attempts_after_blackhole,primary_ack_progress_recovery_empty_attempts_after_blackhole,primary_ack_progress_reinjections_after_blackhole,primary_ack_progress_reinjected_bytes_after_blackhole,primary_ack_progress_feedback_probe_timeouts_after_blackhole,primary_ack_progress_feedback_probes_after_blackhole,primary_ack_progress_feedback_probe_bytes_after_blackhole,secondary_ack_progress_recovery_timeouts_after_blackhole,secondary_ack_progress_recovery_attempts_after_blackhole,secondary_ack_progress_recovery_empty_attempts_after_blackhole,secondary_ack_progress_reinjections_after_blackhole,secondary_ack_progress_reinjected_bytes_after_blackhole,secondary_ack_progress_feedback_probe_timeouts_after_blackhole,secondary_ack_progress_feedback_probes_after_blackhole,secondary_ack_progress_feedback_probe_bytes_after_blackhole,first_primary_ack_progress_timeout_ms,first_primary_ack_progress_reinjection_ms,first_primary_ack_progress_feedback_probe_ms,primary_final_ack_progress_timer_armed,first_secondary_stream_retransmit_ms,first_secondary_fresh_stream_ms,first_receiver_secondary_cross_path_ack_ms,primary_path_ack_escape_requests_after_blackhole,secondary_path_ack_escape_requests_after_blackhole,receiver_primary_path_ack_escape_acks_after_blackhole,receiver_secondary_path_ack_escape_acks_after_blackhole,primary_stream_gap_rescue_probes_after_blackhole,primary_stream_gap_rescue_bytes_after_blackhole,secondary_stream_gap_rescue_probes_after_blackhole,secondary_stream_gap_rescue_bytes_after_blackhole\n",
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
        writeln!(
            csv,
            ",{},{},{},{},{},{},{},{}",
            after_primary.path_ack_escape_requests,
            after_secondary.path_ack_escape_requests,
            receiver_primary.path_ack_escape_acks,
            receiver_secondary.path_ack_escape_acks,
            after_primary.stream_gap_rescue_probes,
            after_primary.stream_gap_rescue_bytes,
            after_secondary.stream_gap_rescue_probes,
            after_secondary.stream_gap_rescue_bytes,
        )?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_stream_state_csv(path: &str, observations: &[FormalFailoverObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "direction,round,line_one_seed,line_two_seed,elapsed_after_fault_ms,stream_id,sender_fully_acked_offset,sender_unacknowledged_bytes,sender_lowest_retransmit_offset,sender_retransmit_bytes,sender_offset,sender_max_stream_data,sender_stream_flow_control_blocked,sender_connection_flow_control_blocked,sender_connection_data,sender_max_data,sender_max_data_blocked,receiver_contiguous_offset,receiver_highest_offset,receiver_buffered_after_gap_bytes,feedback_debt_bytes,retransmit_target_minus_receiver_bytes,receiver_sent_max_stream_data,receiver_current_max_stream_data,receiver_max_stream_data_pending,receiver_max_stream_data_in_flight_packets,receiver_data,receiver_max_data,receiver_sent_max_data,receiver_max_data_pending,receiver_max_data_in_flight_packets,response_sender_fully_acked_offset,response_sender_unacknowledged_bytes,response_sender_lowest_retransmit_offset,response_sender_retransmit_bytes,response_sender_offset,response_sender_max_stream_data,response_sender_flow_control_blocked,response_sender_connection_blocked,response_receiver_contiguous_offset,response_receiver_highest_offset,secondary_lost_packets,secondary_stream_retransmit_bytes,secondary_pto_timeouts,secondary_rtt_ms,secondary_pto_ms,secondary_cwnd,secondary_bytes_in_flight,secondary_ack_eliciting_in_flight,secondary_tracked_sent_packets,secondary_tracked_ack_eliciting_packets,secondary_latest_ack_eliciting_pn,secondary_pto_count,secondary_loss_timer_armed,receiver_primary_tracked_max_data_packets,receiver_primary_tracked_max_stream_data_packets,receiver_primary_pto_count,receiver_primary_loss_timer_armed,receiver_primary_stream_fresh_bytes,receiver_secondary_tracked_max_data_packets,receiver_secondary_tracked_max_stream_data_packets,receiver_secondary_pto_count,receiver_secondary_loss_timer_armed,receiver_secondary_stream_fresh_bytes,receiver_secondary_stream_retransmit_bytes,receiver_secondary_lost_packets,receiver_secondary_pto_timeouts,receiver_secondary_bytes_in_flight,receiver_secondary_ack_eliciting_in_flight,receiver_secondary_tracked_sent_packets,receiver_secondary_tracked_ack_eliciting_packets,secondary_stream_gap_rescue_probes,secondary_stream_gap_rescue_bytes\n",
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
