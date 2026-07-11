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

    const RESULT_PATH: &str = "benchmark-results/2026-07-12-pto-hedge-formal-a-v2.csv";
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");

    println!();
    println!("FlowWeave / 织流：正式 A 组双向持续换网实验");
    println!("每场在同一条 QUIC 业务流上持续发送 30 秒，第 10 秒把主路改为 100% 丢包。");
    println!("接收端逐条校验序号和内容，并以故障后的最大相邻到达间隔衡量断流。");

    let mut observations = Vec::with_capacity(
        FailoverDirection::ALL.len() * SEED_PAIRS.len() * PtoRecovery::CANDIDATES.len(),
    );
    write_formal_failover_csv(RESULT_PATH, &observations)?;

    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());
        for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
            let round = round_index + 1;
            let order = recovery_screening_order(round_index + direction_index);
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
    let total_udp = observation
        .report
        .primary_bytes_after_blackhole
        .saturating_add(observation.report.secondary_bytes_after_blackhole);
    let total_hedges = observation
        .report
        .primary_pto_hedges
        .saturating_add(observation.report.secondary_pto_hedges);
    let total_hedge_bytes = observation
        .report
        .primary_pto_hedge_bytes
        .saturating_add(observation.report.secondary_pto_hedge_bytes);
    let pre_blackhole_hedges = observation
        .report
        .primary_pto_hedges_before_blackhole
        .saturating_add(observation.report.secondary_pto_hedges_before_blackhole);
    let pre_blackhole_hedge_bytes = observation
        .report
        .primary_pto_hedge_bytes_before_blackhole
        .saturating_add(
            observation
                .report
                .secondary_pto_hedge_bytes_before_blackhole,
        );

    println!("- {}", observation.pto_recovery.description());
    println!(
        "  完整 {}，恢复 {}，断流 {}，持续 {}，记录 {} 条 / {} 字节",
        yes_or_no(observation.report.data_intact),
        yes_or_no(observation.report.recovered),
        optional_milliseconds(observation.report.recovery_gap),
        optional_milliseconds(observation.report.transfer_duration),
        observation.report.records_received,
        observation.report.application_bytes_received,
    );
    println!(
        "  黑洞前主路/备用路首次数据 {} / {} 字节，对冲 {} 次 / {} 字节；黑洞后 UDP {} 字节，对冲 {} 次 / {} 字节",
        observation.report.primary_fresh_bytes_before_blackhole,
        observation.report.secondary_fresh_bytes_before_blackhole,
        pre_blackhole_hedges,
        pre_blackhole_hedge_bytes,
        total_udp,
        total_hedges,
        total_hedge_bytes,
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
                    && observation.pto_recovery == PtoRecovery::CrossPathHedge
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
        let primary_used = candidates
            .iter()
            .filter(|observation| observation.report.primary_fresh_bytes_before_blackhole > 0)
            .count();
        let gaps: Vec<_> = candidates
            .iter()
            .filter_map(|observation| observation.report.recovery_gap)
            .map(milliseconds)
            .collect();
        let gap_summary = (!gaps.is_empty()).then(|| NumericSummary::from_samples(gaps));
        let pass = candidates.len() == SEED_PAIRS.len()
            && intact == SEED_PAIRS.len()
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
            "- {}：完整 {intact}/{total}，恢复 {recovered}/{total}，黑洞前主路承载数据 {primary_used}/{total}，P95 {}，黑洞后 UDP 相对基线中位 {:.2}%，门槛 {}",
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

fn formal_failover_udp_bytes(report: &SustainedFailoverReport) -> u64 {
    report
        .primary_bytes_after_blackhole
        .saturating_add(report.secondary_bytes_after_blackhole)
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
        "direction,round,line_one_seed,line_two_seed,recovery,recovered,data_intact,recovery_gap_ms,transfer_duration_ms,records_received,application_bytes_received,failure_reason,primary_fresh_bytes_before_blackhole,secondary_fresh_bytes_before_blackhole,primary_pto_hedges_before_blackhole,secondary_pto_hedges_before_blackhole,primary_pto_hedge_bytes_before_blackhole,secondary_pto_hedge_bytes_before_blackhole,primary_udp_bytes_after_blackhole,secondary_udp_bytes_after_blackhole,total_udp_bytes_after_blackhole,primary_lost_packets,secondary_lost_packets,pto_hedges_after_blackhole,pto_hedge_bytes_after_blackhole,primary_path_open,secondary_path_open\n",
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
        let total_udp = formal_failover_udp_bytes(&observation.report);
        let total_hedges = observation
            .report
            .primary_pto_hedges
            .saturating_add(observation.report.secondary_pto_hedges);
        let total_hedge_bytes = observation
            .report
            .primary_pto_hedge_bytes
            .saturating_add(observation.report.secondary_pto_hedge_bytes);

        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            observation.direction.description(),
            observation.round,
            observation.seeds.line_one,
            observation.seeds.line_two,
            observation.pto_recovery.description(),
            observation.report.recovered,
            observation.report.data_intact,
            recovery_gap_ms,
            transfer_duration_ms,
            observation.report.records_received,
            observation.report.application_bytes_received,
            failure_reason,
            observation.report.primary_fresh_bytes_before_blackhole,
            observation.report.secondary_fresh_bytes_before_blackhole,
            observation.report.primary_pto_hedges_before_blackhole,
            observation.report.secondary_pto_hedges_before_blackhole,
            observation.report.primary_pto_hedge_bytes_before_blackhole,
            observation
                .report
                .secondary_pto_hedge_bytes_before_blackhole,
            observation.report.primary_bytes_after_blackhole,
            observation.report.secondary_bytes_after_blackhole,
            total_udp,
            observation.report.primary_lost_packets,
            observation.report.secondary_lost_packets,
            total_hedges,
            total_hedge_bytes,
            observation.report.primary_path_open,
            observation.report.secondary_path_open,
        )?;
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

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn yes_or_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}

fn lab_error(message: impl Into<String>) -> flowweave_lab::LabError {
    io::Error::other(message.into()).into()
}
