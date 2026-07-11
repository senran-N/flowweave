use std::{
    env,
    fmt::Write as _,
    fs, io,
    net::Ipv4Addr,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use flowweave_lab::{
    CapacityProbeConfig, CapacityProbeReport, DatagramMeasurement, FailoverReport, LabResult,
    MultipathScheduler, NetworkBenchmarkConfig, NetworkBenchmarkReport, PathMode,
    SustainedBenchmarkConfig, run_blackhole_failover, run_local_capacity_probe,
    run_network_benchmark, run_sustained_network_benchmark,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const SCREENING_TRANSFER_SIZE: usize = 2 * MIB;
const LONG_WARMUP_DURATION: Duration = Duration::from_secs(2);
const LONG_MEASUREMENT_DURATION: Duration = Duration::from_secs(20);
const LONG_CHUNK_SIZE: usize = 512 * KIB;
const CAPACITY_PROBE_RECEIVER_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum CapacityProbePath {
    LineOne,
    LineTwo,
}

impl CapacityProbePath {
    const ALL: [Self; 2] = [Self::LineOne, Self::LineTwo];

    fn description(self) -> &'static str {
        match self {
            Self::LineOne => "线路一",
            Self::LineTwo => "线路二",
        }
    }

    fn source_ip(self) -> Ipv4Addr {
        match self {
            Self::LineOne => Ipv4Addr::new(127, 0, 0, 1),
            Self::LineTwo => Ipv4Addr::new(127, 0, 0, 2),
        }
    }

    fn expected_mbps(self) -> f64 {
        match self {
            Self::LineOne => 8.0,
            Self::LineTwo => 25.0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CapacityProbeCandidate {
    PacketTrain,
    ChirpCurveFit,
}

impl CapacityProbeCandidate {
    const ALL: [Self; 2] = [Self::PacketTrain, Self::ChirpCurveFit];

    fn description(self) -> &'static str {
        match self {
            Self::PacketTrain => "背靠背 Packet Train",
            Self::ChirpCurveFit => "Chirp 排队曲线拟合",
        }
    }

    fn config(self, path: CapacityProbePath) -> CapacityProbeConfig {
        match self {
            Self::PacketTrain => {
                CapacityProbeConfig::packet_train(path.source_ip(), CAPACITY_PROBE_RECEIVER_IP)
            }
            Self::ChirpCurveFit => {
                CapacityProbeConfig::chirp(path.source_ip(), CAPACITY_PROBE_RECEIVER_IP)
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CapacityProbeParticipant {
    path: CapacityProbePath,
    candidate: CapacityProbeCandidate,
}

impl CapacityProbeParticipant {
    const ALL: [Self; 4] = [
        Self {
            path: CapacityProbePath::LineOne,
            candidate: CapacityProbeCandidate::PacketTrain,
        },
        Self {
            path: CapacityProbePath::LineTwo,
            candidate: CapacityProbeCandidate::PacketTrain,
        },
        Self {
            path: CapacityProbePath::LineOne,
            candidate: CapacityProbeCandidate::ChirpCurveFit,
        },
        Self {
            path: CapacityProbePath::LineTwo,
            candidate: CapacityProbeCandidate::ChirpCurveFit,
        },
    ];

    fn description(self) -> String {
        format!(
            "{} / {}",
            self.path.description(),
            self.candidate.description()
        )
    }

    fn config(self) -> CapacityProbeConfig {
        self.candidate.config(self.path)
    }
}

struct CapacityProbeObservation {
    round: usize,
    seeds: NetemSeeds,
    participant: CapacityProbeParticipant,
    report: CapacityProbeReport,
    cpu_time: Duration,
    cpu_utilization_percent: f64,
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
        benchmark_multipath_candidates(normal_line_one, normal_line_two, 512 * KIB, 48).await?;
    for report in &normal_multipath {
        print_benchmark(report);
    }

    println!();
    println!("场景二：传输中主线路突然变为 100% 丢包");
    for scheduler in MultipathScheduler::CANDIDATES {
        apply_profiles(normal_line_one, normal_line_two, SEED_PAIRS[0])?;
        let failover = run_blackhole_failover(scheduler, || {
            replace_line_profile(
                "1:1",
                "10:",
                LinkProfile::new("20ms", "100%", "20mbit"),
                SEED_PAIRS[0].line_one,
            )
        })
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
        benchmark_multipath_candidates(high_loss_line_one, high_loss_line_two, 384 * KIB, 72)
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

#[test]
#[ignore = "必须通过 scripts/run_netem_lab.sh probe 在隔离网络命名空间中运行"]
fn capacity_probe_five_seed_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    const RESULT_PATH: &str = "benchmark-results/2026-07-11-capacity-probe-screening.csv";
    let profiles = AggregationScenario::Heterogeneous.profiles();
    let one_round_probe_bytes: usize = CapacityProbeParticipant::ALL
        .iter()
        .map(|participant| participant.config().estimated_wire_bytes())
        .sum();
    let byte_budget = SCREENING_TRANSFER_SIZE / 20;
    if one_round_probe_bytes > byte_budget {
        return Err(lab_error(format!(
            "容量传感器一轮预计发送 {one_round_probe_bytes} 字节，超过 2 MiB 短流的 5% 预算 {byte_budget} 字节"
        )));
    }

    println!();
    println!("FlowWeave / 织流：独立容量传感器五种子实验");
    println!("目标不是调度数据，而是先证明能可靠区分 8 Mbit/s 与 25 Mbit/s。");
    println!(
        "同一轮比较两个候选、两条线路，共计约 {one_round_probe_bytes} 字节，占 2 MiB 短流 {:.2}%。",
        one_round_probe_bytes as f64 / SCREENING_TRANSFER_SIZE as f64 * 100.0
    );
    println!("探测耗时、丢包、内核接收时间戳异常和 CPU 全部计账，没有免费预热。");

    let ticks_per_second = process_clock_ticks_per_second()?;
    let mut observations =
        Vec::with_capacity(SEED_PAIRS.len() * CapacityProbeParticipant::ALL.len());
    write_capacity_probe_csv(RESULT_PATH, &observations)?;

    for (round_index, seeds) in SEED_PAIRS.iter().copied().enumerate() {
        let round = round_index + 1;
        let order = capacity_probe_order(round_index);
        println!();
        println!(
            "第 {round} 轮：线路一种子 {}，线路二种子 {}；顺序 {}",
            seeds.line_one,
            seeds.line_two,
            order
                .iter()
                .map(|participant| participant.description())
                .collect::<Vec<_>>()
                .join(" → ")
        );

        for participant in order {
            apply_profiles(profiles.0, profiles.1, seeds)?;
            let cpu_before = read_process_cpu_ticks()?;
            let wall_started = Instant::now();
            let report = run_local_capacity_probe(participant.config())?;
            let wall_elapsed = wall_started.elapsed();
            let cpu_ticks = read_process_cpu_ticks()?.saturating_sub(cpu_before);
            let cpu_time = Duration::from_secs_f64(cpu_ticks as f64 / ticks_per_second as f64);
            let cpu_utilization_percent = if wall_elapsed.is_zero() {
                0.0
            } else {
                cpu_time.as_secs_f64() / wall_elapsed.as_secs_f64() * 100.0
            };
            print_capacity_probe_observation(
                participant,
                &report,
                cpu_time,
                cpu_utilization_percent,
            );
            observations.push(CapacityProbeObservation {
                round,
                seeds,
                participant,
                report,
                cpu_time,
                cpu_utilization_percent,
            });
            write_capacity_probe_csv(RESULT_PATH, &observations)?;
        }
    }

    print_capacity_probe_summary(&observations, one_round_probe_bytes);
    println!();
    println!("原始容量探测数据已写入 {RESULT_PATH}");
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

fn capacity_probe_order(round_index: usize) -> Vec<CapacityProbeParticipant> {
    let mut order = CapacityProbeParticipant::ALL.to_vec();
    let len = order.len();
    order.rotate_left(round_index % len);
    if round_index % 2 == 1 {
        order.reverse();
    }
    order
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
    if env::var("FLOWWEAVE_LAB_MODE").as_deref() == Ok("probe") {
        replace_probe_line_profile("1:1", "10:", "10:1", "11:", line_one, seeds.line_one)?;
        return replace_probe_line_profile("1:2", "20:", "20:1", "21:", line_two, seeds.line_two);
    }

    replace_line_profile("1:1", "10:", line_one, seeds.line_one)?;
    replace_line_profile("1:2", "20:", line_two, seeds.line_two)
}

fn replace_probe_line_profile(
    parent: &'static str,
    shaper_handle: &'static str,
    netem_parent: &'static str,
    netem_handle: &'static str,
    profile: LinkProfile,
    seed: u32,
) -> LabResult<()> {
    let rate_mbit = profile
        .rate
        .strip_suffix("mbit")
        .ok_or_else(|| lab_error("容量探针限速只接受 mbit 单位"))?
        .parse::<u64>()?;
    let peak_rate = format!("{}kbit", rate_mbit.saturating_mul(1_000).saturating_add(1));
    run_tc(&[
        "qdisc",
        "replace",
        "dev",
        "lo",
        "parent",
        parent,
        "handle",
        shaper_handle,
        "tbf",
        "rate",
        profile.rate,
        "burst",
        "32kb",
        "peakrate",
        &peak_rate,
        "minburst",
        "1600",
        "latency",
        "100ms",
    ])?;

    let seed = seed.to_string();
    run_tc(&[
        "qdisc",
        "replace",
        "dev",
        "lo",
        "parent",
        netem_parent,
        "handle",
        netem_handle,
        "netem",
        "limit",
        "10000",
        "delay",
        profile.delay,
        "loss",
        profile.loss,
        "seed",
        &seed,
    ])
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
    println!(
        "  流传输：{} 字节，耗时 {:.2} ms，吞吐量 {:.2} Mbit/s",
        report.transfer_size,
        milliseconds(report.transfer_duration),
        report.throughput_mbps
    );
    print_datagrams(&report.datagrams);
    println!(
        "  线路一：首次流数据 {} 字节，重传流数据 {} 字节，UDP 总发送 {} 字节，丢失 {} 包，最终 RTT {:.2} ms",
        report.line_one.fresh_stream_bytes_sent,
        report.line_one.retransmitted_stream_bytes_sent,
        report.line_one.udp_bytes_sent,
        report.line_one.lost_packets,
        milliseconds(report.line_one.final_rtt)
    );
    println!(
        "  线路二：首次流数据 {} 字节，重传流数据 {} 字节，UDP 总发送 {} 字节，丢失 {} 包，最终 RTT {:.2} ms",
        report.line_two.fresh_stream_bytes_sent,
        report.line_two.retransmitted_stream_bytes_sent,
        report.line_two.udp_bytes_sent,
        report.line_two.lost_packets,
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
    println!(
        "- 实验设置的单路径空闲判定上限：{:.0} ms",
        milliseconds(report.configured_path_idle_timeout)
    );
    println!("- 是否在原连接上恢复：{}", yes_or_no(report.recovered));
    match report.recovery_time {
        Some(duration) => println!("- 从断路到恢复：{:.2} ms", milliseconds(duration)),
        None => println!(
            "- 未恢复原因：{}",
            report.failure_reason.as_deref().unwrap_or("原因未知")
        ),
    }
    println!(
        "- 断路后主线路发送 {} 字节、丢失 {} 包",
        report.primary_bytes_after_blackhole, report.primary_lost_packets
    );
    println!(
        "- 断路后备用线路发送 {} 字节、丢失 {} 包",
        report.secondary_bytes_after_blackhole, report.secondary_lost_packets
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

fn print_capacity_probe_observation(
    participant: CapacityProbeParticipant,
    report: &CapacityProbeReport,
    cpu_time: Duration,
    cpu_utilization_percent: f64,
) {
    let estimate = report
        .estimated_mbps
        .map(|value| format!("{value:.2} Mbit/s"))
        .unwrap_or_else(|| "无可用估计".to_owned());
    let quality = if report.usable {
        "可用".to_owned()
    } else {
        format!(
            "拒绝：{}",
            report.rejection_reason.as_deref().unwrap_or("原因未知")
        )
    };
    println!(
        "- {}：估计 {estimate}（真实 {:.0}）；{quality}；收到 {}/{}（内核时间戳 {}，缺失 {}），耗时 {:.2} ms，时间戳异常 {}，CPU {:.2} ms / {:.1}%",
        participant.description(),
        participant.path.expected_mbps(),
        report.received_packets,
        report.sent_packets,
        report.timestamped_packets,
        report.missing_receive_timestamps,
        milliseconds(report.elapsed),
        report.timestamp_anomalies,
        milliseconds(cpu_time),
        cpu_utilization_percent,
    );
    match participant.candidate {
        CapacityProbeCandidate::PacketTrain => println!(
            "  Packet Train 包间隔波动系数：{}",
            optional_number(report.packet_train_gap_cv, 4)
        ),
        CapacityProbeCandidate::ChirpCurveFit => println!(
            "  Chirp 排队信号 {} 微秒，拟合 RMSE {} 微秒，归一化误差 {}",
            optional_number(report.queue_signal_us, 2),
            optional_number(report.fit_rmse_us, 2),
            optional_number(report.normalized_fit_error, 4),
        ),
    }
}

fn print_capacity_probe_summary(
    observations: &[CapacityProbeObservation],
    one_round_probe_bytes: usize,
) {
    println!();
    println!("五种子容量传感器汇总：");
    println!(
        "提前锁定门槛：快慢排名 5/5 正确、容量比例误差每轮不超过 20%、一轮探测不超过 2 MiB 的 5%。"
    );

    let expected_ratio =
        CapacityProbePath::LineTwo.expected_mbps() / CapacityProbePath::LineOne.expected_mbps();
    for candidate in CapacityProbeCandidate::ALL {
        let matching: Vec<_> = observations
            .iter()
            .filter(|observation| observation.participant.candidate == candidate)
            .collect();
        let usable = matching
            .iter()
            .filter(|observation| observation.report.usable)
            .count();
        let losses: usize = matching
            .iter()
            .map(|observation| observation.report.lost_packets)
            .sum();
        let timestamp_anomalies: usize = matching
            .iter()
            .map(|observation| observation.report.timestamp_anomalies)
            .sum();
        let cpu = NumericSummary::from_samples(
            matching
                .iter()
                .map(|observation| observation.cpu_utilization_percent),
        );

        let mut rank_correct = 0;
        let mut ratio_passes = 0;
        let mut ratio_errors = Vec::new();
        for round in 1..=SEED_PAIRS.len() {
            let line_one =
                capacity_estimate(observations, candidate, CapacityProbePath::LineOne, round);
            let line_two =
                capacity_estimate(observations, candidate, CapacityProbePath::LineTwo, round);
            if let (Some(line_one), Some(line_two)) = (line_one, line_two) {
                if line_two > line_one {
                    rank_correct += 1;
                }
                let ratio_error = ((line_two / line_one) / expected_ratio - 1.0).abs() * 100.0;
                if ratio_error <= 20.0 {
                    ratio_passes += 1;
                }
                ratio_errors.push(ratio_error);
            }
        }
        let ratio_summary = (!ratio_errors.is_empty())
            .then(|| NumericSummary::from_samples(ratio_errors.iter().copied()));
        let retained_probe_bytes: usize = CapacityProbePath::ALL
            .iter()
            .map(|path| candidate.config(*path).estimated_wire_bytes())
            .sum();
        let passed = usable == SEED_PAIRS.len() * CapacityProbePath::ALL.len()
            && rank_correct == SEED_PAIRS.len()
            && ratio_passes == SEED_PAIRS.len()
            && one_round_probe_bytes <= SCREENING_TRANSFER_SIZE / 20;

        println!();
        println!(
            "- {}：{}",
            candidate.description(),
            if passed {
                "通过初筛"
            } else {
                "未通过初筛"
            }
        );
        println!(
            "  可用读数 {usable}/{}；快慢排名 {rank_correct}/5；比例误差 20% 门槛 {ratio_passes}/5",
            SEED_PAIRS.len() * CapacityProbePath::ALL.len(),
        );
        if let Some(summary) = ratio_summary {
            println!(
                "  容量比例误差：中位 {:.2}%，最差/最高 {:.2}%，范围 {:.2}%～{:.2}%",
                summary.median, summary.maximum, summary.minimum, summary.maximum
            );
        } else {
            println!("  容量比例误差：没有成对可用读数");
        }
        println!(
            "  若只保留该方法，每次测两条路约 {retained_probe_bytes} 字节，占 2 MiB 短流 {:.2}%",
            retained_probe_bytes as f64 / SCREENING_TRANSFER_SIZE as f64 * 100.0
        );
        println!(
            "  总丢包 {losses}，时间戳异常 {timestamp_anomalies}；CPU 中位 {:.1}%，最高 {:.1}%",
            cpu.median, cpu.maximum
        );
    }
}

fn capacity_estimate(
    observations: &[CapacityProbeObservation],
    candidate: CapacityProbeCandidate,
    path: CapacityProbePath,
    round: usize,
) -> Option<f64> {
    observations
        .iter()
        .find(|observation| {
            observation.round == round
                && observation.participant.candidate == candidate
                && observation.participant.path == path
                && observation.report.usable
        })
        .and_then(|observation| observation.report.estimated_mbps)
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
        "scenario,round,line_one_seed,line_two_seed,participant,throughput_mbps,transfer_ms,line_one_fresh_bytes,line_two_fresh_bytes,line_one_retransmit_bytes,line_two_retransmit_bytes,total_udp_bytes,wire_ratio,minimum_effective_share_percent,best_single_ratio,cpu_time_ms,cpu_utilization_percent,peak_rss_kib\n",
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
            "{},{},{},{},{},{:.6},{:.3},{},{},{},{},{},{:.6},{:.6},{},{:.3},{:.6},{}",
            observation.scenario.description(),
            observation.round,
            observation.seeds.line_one,
            observation.seeds.line_two,
            observation.participant.description(),
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
        )?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_capacity_probe_csv(
    path: &str,
    observations: &[CapacityProbeObservation],
) -> LabResult<()> {
    let mut csv = String::from(
        "round,line_one_seed,line_two_seed,path,method,expected_mbps,estimated_mbps,usable,rejection_reason,sent_packets,received_packets,timestamped_packets,missing_receive_timestamps,lost_packets,payload_bytes_sent,estimated_wire_bytes_sent,elapsed_ms,timestamp_anomalies,max_consecutive_timestamp_anomalies,out_of_order_packets,fit_rmse_us,normalized_fit_error,queue_signal_us,packet_train_gap_cv,cpu_time_ms,cpu_utilization_percent\n",
    );

    for observation in observations {
        writeln!(
            csv,
            "{},{},{},{},{},{:.6},{},{},{},{},{},{},{},{},{},{},{:.3},{},{},{},{},{},{},{},{:.3},{:.6}",
            observation.round,
            observation.seeds.line_one,
            observation.seeds.line_two,
            observation.participant.path.description(),
            observation.participant.candidate.description(),
            observation.participant.path.expected_mbps(),
            optional_csv_number(observation.report.estimated_mbps),
            observation.report.usable,
            csv_field(observation.report.rejection_reason.as_deref().unwrap_or("")),
            observation.report.sent_packets,
            observation.report.received_packets,
            observation.report.timestamped_packets,
            observation.report.missing_receive_timestamps,
            observation.report.lost_packets,
            observation.report.payload_bytes_sent,
            observation.report.estimated_wire_bytes_sent,
            milliseconds(observation.report.elapsed),
            observation.report.timestamp_anomalies,
            observation.report.maximum_consecutive_timestamp_anomalies,
            observation.report.out_of_order_packets,
            optional_csv_number(observation.report.fit_rmse_us),
            optional_csv_number(observation.report.normalized_fit_error),
            optional_csv_number(observation.report.queue_signal_us),
            optional_csv_number(observation.report.packet_train_gap_cv),
            milliseconds(observation.cpu_time),
            observation.cpu_utilization_percent,
        )?;
    }

    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn optional_number(value: Option<f64>, precision: usize) -> String {
    value
        .map(|value| format!("{value:.precision$}"))
        .unwrap_or_else(|| "无".to_owned())
}

fn optional_csv_number(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.6}")).unwrap_or_default()
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn read_process_cpu_ticks() -> LabResult<u64> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let fields = stat
        .rfind(") ")
        .map(|index| &stat[index + 2..])
        .ok_or_else(|| lab_error("无法解析 /proc/self/stat 中的进程名称"))?;
    let mut fields = fields.split_whitespace();
    let user_ticks = fields
        .nth(11)
        .ok_or_else(|| lab_error("/proc/self/stat 缺少用户 CPU 时间"))?
        .parse::<u64>()?;
    let system_ticks = fields
        .next()
        .ok_or_else(|| lab_error("/proc/self/stat 缺少系统 CPU 时间"))?
        .parse::<u64>()?;
    Ok(user_ticks.saturating_add(system_ticks))
}

fn process_clock_ticks_per_second() -> LabResult<u64> {
    static TICKS_PER_SECOND: AtomicU64 = AtomicU64::new(0);
    let cached = TICKS_PER_SECOND.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }

    let output = Command::new("getconf").arg("CLK_TCK").output()?;
    if !output.status.success() {
        return Err(lab_error(format!(
            "getconf CLK_TCK 失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let ticks = String::from_utf8(output.stdout)?.trim().parse::<u64>()?;
    if ticks == 0 {
        return Err(lab_error("getconf CLK_TCK 返回了 0"));
    }
    TICKS_PER_SECOND.store(ticks, Ordering::Relaxed);
    Ok(ticks)
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
