use std::{env, fmt::Write as _, fs, process::Command, time::Duration};

use flowweave_lab::{
    FailoverDirection, LabResult, MptcpFailoverConfig, MptcpFailoverReport, MptcpPathMode,
    MptcpThroughputConfig, MptcpThroughputReport, run_mptcp_failover, run_mptcp_throughput,
};

const KIB: usize = 1024;
const A_DURATION: Duration = Duration::from_secs(30);
const A_FAILURE_AFTER: Duration = Duration::from_secs(10);
const A_CHUNK_SIZE: usize = 16 * KIB;
const B_WARMUP: Duration = Duration::from_secs(2);
const B_SMOKE_MEASUREMENT: Duration = Duration::from_secs(5);
const B_FORMAL_MEASUREMENT: Duration = Duration::from_secs(20);
const B_CHUNK_SIZE: usize = 16 * KIB;
const FLOWWEAVE_A_FORWARD_MEDIAN_MS: f64 = 576.98;
const FLOWWEAVE_A_REVERSE_MEDIAN_MS: f64 = 615.11;
const FLOWWEAVE_B_BALANCED_MEDIAN_MBPS: f64 = 26.579_653;
const FLOWWEAVE_B_HETEROGENEOUS_MEDIAN_MBPS: f64 = 27.509_019;

const A_SMOKE_PATH: &str = "benchmark-results/2026-07-14-linux-mptcp-a-smoke-v1.csv";
const A_FORMAL_PATH: &str = "benchmark-results/2026-07-14-linux-mptcp-a-formal-10-v1.csv";
const B_SMOKE_PATH: &str = "benchmark-results/2026-07-14-linux-mptcp-b-smoke-v1.csv";
const B_FORMAL_PATH: &str = "benchmark-results/2026-07-14-linux-mptcp-b-formal-30-v1.csv";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Wire,
    ASmoke,
    AFormal,
    BSmoke,
    BFormal,
}

impl Mode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "wire" => Some(Self::Wire),
            "a-smoke" => Some(Self::ASmoke),
            "a-formal" => Some(Self::AFormal),
            "b-smoke" => Some(Self::BSmoke),
            "b-formal" => Some(Self::BFormal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregationScenario {
    Balanced,
    Heterogeneous,
}

impl AggregationScenario {
    const ALL: [Self; 2] = [Self::Balanced, Self::Heterogeneous];

    const fn description(self) -> &'static str {
        match self {
            Self::Balanced => "平衡 15+15 Mbit/s",
            Self::Heterogeneous => "异构 8+25 Mbit/s",
        }
    }

    const fn profiles(self) -> (LinkProfile, LinkProfile) {
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

    const fn flowweave_median(self) -> f64 {
        match self {
            Self::Balanced => FLOWWEAVE_B_BALANCED_MEDIAN_MBPS,
            Self::Heterogeneous => FLOWWEAVE_B_HETEROGENEOUS_MEDIAN_MBPS,
        }
    }
}

struct AObservation {
    direction: FailoverDirection,
    round: usize,
    seeds: NetemSeeds,
    payload_seed: u8,
    report: MptcpFailoverReport,
}

struct BObservation {
    scenario: AggregationScenario,
    round: usize,
    seeds: NetemSeeds,
    payload_seed: u8,
    report: MptcpThroughputReport,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("MPTCP 对照失败：{error}");
        std::process::exit(1);
    }
}

async fn run() -> LabResult<()> {
    let mode = env::args()
        .nth(1)
        .as_deref()
        .and_then(Mode::parse)
        .ok_or_else(|| {
            lab_error("用法：flowweave-mptcp-comparison wire|a-smoke|a-formal|b-smoke|b-formal")
        })?;
    verify_isolated_environment()?;
    match mode {
        Mode::Wire => run_wire().await,
        Mode::ASmoke => run_a_matrix(A_SMOKE_PATH, &SEED_PAIRS[..1]).await,
        Mode::AFormal => run_a_matrix(A_FORMAL_PATH, &SEED_PAIRS).await,
        Mode::BSmoke => run_b_matrix(B_SMOKE_PATH, B_SMOKE_MEASUREMENT, &SEED_PAIRS[..1]).await,
        Mode::BFormal => run_b_matrix(B_FORMAL_PATH, B_FORMAL_MEASUREMENT, &SEED_PAIRS).await,
    }
}

async fn run_wire() -> LabResult<()> {
    println!("Linux MPTCP + TLS 1.3 接线诊断");
    let scenario = AggregationScenario::Balanced;
    let (line_one, line_two) = scenario.profiles();
    apply_profiles(line_one, line_two, SEED_PAIRS[0])?;
    let report = run_mptcp_throughput(MptcpThroughputConfig::new(
        MptcpPathMode::Multipath,
        Duration::from_millis(500),
        Duration::from_secs(1),
        B_CHUNK_SIZE,
        193,
    ))
    .await?;
    print_b_report(&report);
    print_tc_statistics()?;
    if !report.infrastructure_pass() {
        return Err(lab_error("MPTCP 接线诊断没有通过基础设施门槛"));
    }
    println!("MPTCP 接线诊断通过");
    Ok(())
}

async fn run_a_matrix(result_path: &str, seeds: &[NetemSeeds]) -> LabResult<()> {
    ensure_result_absent(result_path)?;
    let normal_line_one = LinkProfile::new("20ms", "0.1%", "20mbit");
    let normal_line_two = LinkProfile::new("80ms", "1%", "20mbit");
    let mut observations = Vec::with_capacity(FailoverDirection::ALL.len() * seeds.len());
    write_a_csv(result_path, &observations)?;

    println!("Linux MPTCP：A 组原 meta socket 故障切换对照");
    println!("每场 30 秒，第 10 秒把线路一改为 100% 丢包；TLS 1.3、default scheduler、Cubic。");
    for (direction_index, direction) in FailoverDirection::ALL.into_iter().enumerate() {
        println!();
        println!("传输方向：{}", direction.description());
        for (round_index, seeds) in seeds.iter().copied().enumerate() {
            let round = round_index + 1;
            let payload_seed = 211_u8
                .wrapping_add(round as u8)
                .wrapping_add((direction_index as u8).wrapping_mul(17));
            println!(
                "第 {round} 轮：线路种子 {}/{}，业务种子 {payload_seed}",
                seeds.line_one, seeds.line_two
            );
            apply_profiles(normal_line_one, normal_line_two, seeds)?;
            let report = run_mptcp_failover(
                MptcpFailoverConfig::new(
                    direction,
                    A_DURATION,
                    A_FAILURE_AFTER,
                    A_CHUNK_SIZE,
                    payload_seed,
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
            print_a_report(&report);
            let infrastructure_pass = report.infrastructure_pass();
            observations.push(AObservation {
                direction,
                round,
                seeds,
                payload_seed,
                report,
            });
            write_a_csv(result_path, &observations)?;
            if !infrastructure_pass {
                return Err(lab_error(format!(
                    "MPTCP A 组基础设施门槛失败；结果已保留在 {result_path}"
                )));
            }
        }
    }

    print_a_summary(&observations, seeds.len());
    print_tc_statistics()?;
    println!("MPTCP A 组原始数据已写入 {result_path}");
    Ok(())
}

async fn run_b_matrix(
    result_path: &str,
    measurement_duration: Duration,
    seeds: &[NetemSeeds],
) -> LabResult<()> {
    ensure_result_absent(result_path)?;
    let mut observations =
        Vec::with_capacity(AggregationScenario::ALL.len() * seeds.len() * MptcpPathMode::ALL.len());
    write_b_csv(result_path, &observations)?;

    println!("Linux MPTCP：B 组持续单流聚合对照");
    println!(
        "每项预热 {} 秒、测量 {:.0} 秒；default scheduler、Cubic、TLS 1.3。",
        B_WARMUP.as_secs(),
        measurement_duration.as_secs_f64()
    );
    for (scenario_index, scenario) in AggregationScenario::ALL.into_iter().enumerate() {
        let (line_one, line_two) = scenario.profiles();
        println!();
        println!("场景：{}", scenario.description());
        for (round_index, seeds) in seeds.iter().copied().enumerate() {
            let round = round_index + 1;
            let mut participants = MptcpPathMode::ALL.to_vec();
            let participant_count = participants.len();
            participants.rotate_left((scenario_index + round_index) % participant_count);
            if (scenario_index + round_index) % 2 == 1 {
                participants.reverse();
            }
            println!(
                "第 {round} 轮：线路种子 {}/{}；顺序 {}",
                seeds.line_one,
                seeds.line_two,
                participants
                    .iter()
                    .map(|mode| mode.description())
                    .collect::<Vec<_>>()
                    .join(" → ")
            );
            for (participant_index, mode) in participants.into_iter().enumerate() {
                apply_profiles(line_one, line_two, seeds)?;
                let payload_seed = 229_u8
                    .wrapping_add((scenario_index as u8).wrapping_mul(40))
                    .wrapping_add((round_index as u8).wrapping_mul(8))
                    .wrapping_add(participant_index as u8);
                let report = run_mptcp_throughput(MptcpThroughputConfig::new(
                    mode,
                    B_WARMUP,
                    measurement_duration,
                    B_CHUNK_SIZE,
                    payload_seed,
                ))
                .await?;
                print_b_report(&report);
                let infrastructure_pass = report.infrastructure_pass();
                observations.push(BObservation {
                    scenario,
                    round,
                    seeds,
                    payload_seed,
                    report,
                });
                write_b_csv(result_path, &observations)?;
                if !infrastructure_pass {
                    return Err(lab_error(format!(
                        "MPTCP B 组基础设施门槛失败；结果已保留在 {result_path}"
                    )));
                }
            }
        }
    }

    print_b_summary(&observations, seeds.len());
    print_tc_statistics()?;
    println!("MPTCP B 组原始数据已写入 {result_path}");
    Ok(())
}

fn print_a_report(report: &MptcpFailoverReport) {
    println!(
        "- 连续性 {}，故障后恢复 {}，恢复间隔 {}，记录 {}/{}，子流 {}/{}，故障后线路一/二 IPv4 字节 {}/{}，基础设施 {}{}",
        yes_or_no(report.continuity_pass),
        yes_or_no(report.recovered_after_failure),
        report
            .recovery_gap
            .map(|gap| format!("{:.3} ms", milliseconds(gap)))
            .unwrap_or_else(|| "无".to_owned()),
        report.records_before_failure,
        report.records_received,
        report.info_before_failure.subflows_total,
        report.info_after_run.subflows_total,
        report.line_one_ipv4_bytes_after_failure(),
        report.line_two_ipv4_bytes_after_failure(),
        yes_or_no(report.infrastructure_pass()),
        report
            .failure_reason
            .as_deref()
            .map(|reason| format!("；{reason}"))
            .unwrap_or_default(),
    );
}

fn print_b_report(report: &MptcpThroughputReport) {
    println!(
        "- {}：{:.3} Mbit/s，子流 {}/{}, 线路一/二 {:.1}%/{:.1}%，IPv4/app {:.4}x，记录 {}，基础设施 {}",
        report.mode.description(),
        report.throughput_mbps,
        report.info_at_start.subflows_total,
        report.info_at_end.subflows_total,
        report.line_one_share_percent(),
        report.line_two_share_percent(),
        report.ipv4_wire_ratio(),
        report.records_received_in_window,
        yes_or_no(report.infrastructure_pass()),
    );
}

fn print_a_summary(observations: &[AObservation], expected_per_direction: usize) {
    println!();
    println!("MPTCP A 组汇总：");
    let mut mptcp_all_continuous = true;
    let mut flowweave_wins_by_latency = true;
    let mut mptcp_wins_by_latency = true;
    for direction in FailoverDirection::ALL {
        let samples: Vec<_> = observations
            .iter()
            .filter(|observation| observation.direction == direction)
            .collect();
        let continuity = samples
            .iter()
            .filter(|observation| observation.report.continuity_pass)
            .count();
        mptcp_all_continuous &= continuity == expected_per_direction;
        let gaps: Vec<_> = samples
            .iter()
            .filter_map(|observation| observation.report.recovery_gap)
            .map(milliseconds)
            .collect();
        let median = median(gaps);
        let flowweave = match direction {
            FailoverDirection::ClientToServer => FLOWWEAVE_A_FORWARD_MEDIAN_MS,
            FailoverDirection::ServerToClient => FLOWWEAVE_A_REVERSE_MEDIAN_MS,
        };
        flowweave_wins_by_latency &= median.is_some_and(|value| flowweave <= value * 0.70);
        mptcp_wins_by_latency &= median.is_some_and(|value| value <= flowweave * 0.70);
        println!(
            "- {}：连续性 {continuity}/{expected_per_direction}，恢复间隔中位 {}；FlowWeave 冻结中位 {flowweave:.2} ms",
            direction.description(),
            median
                .map(|value| format!("{value:.3} ms"))
                .unwrap_or_else(|| "无有效样本".to_owned()),
        );
    }
    if expected_per_direction == SEED_PAIRS.len() {
        let outcome = if !mptcp_all_continuous {
            "FlowWeave 按连续性分支胜出"
        } else if flowweave_wins_by_latency {
            "FlowWeave 按双向中位低至少 30% 胜出"
        } else if mptcp_wins_by_latency {
            "MPTCP 按双向中位低至少 30% 胜出"
        } else {
            "无决定性差异"
        };
        println!("- 预注册正式结论：{outcome}");
    }
}

fn print_b_summary(observations: &[BObservation], expected_rounds: usize) {
    println!();
    println!("MPTCP B 组汇总：");
    let mut flowweave_wins_all = true;
    let mut mptcp_wins_all = true;
    for scenario in AggregationScenario::ALL {
        let multipath: Vec<_> = observations
            .iter()
            .filter(|observation| {
                observation.scenario == scenario
                    && observation.report.mode == MptcpPathMode::Multipath
            })
            .collect();
        let multipath_median = median(
            multipath
                .iter()
                .map(|observation| observation.report.throughput_mbps)
                .collect(),
        );
        let gate_passes = multipath
            .iter()
            .filter(|observation| {
                let best_single = observations
                    .iter()
                    .filter(|candidate| {
                        candidate.scenario == scenario
                            && candidate.round == observation.round
                            && candidate.report.mode != MptcpPathMode::Multipath
                    })
                    .map(|candidate| candidate.report.throughput_mbps)
                    .fold(0.0_f64, f64::max);
                observation.report.throughput_mbps >= best_single * 1.15
                    && observation.report.line_one_share_percent() >= 10.0
                    && observation.report.line_two_share_percent() >= 10.0
            })
            .count();
        let mptcp = multipath_median.unwrap_or(0.0);
        let flowweave = scenario.flowweave_median();
        flowweave_wins_all &= flowweave >= mptcp * 1.15;
        mptcp_wins_all &= mptcp >= flowweave * 1.15;
        println!(
            "- {}：MPTCP 双路中位 {:.3} Mbit/s，聚合门槛 {gate_passes}/{expected_rounds}；FlowWeave 冻结中位 {flowweave:.3} Mbit/s，FlowWeave/MPTCP {:.3}x",
            scenario.description(),
            mptcp,
            if mptcp == 0.0 { 0.0 } else { flowweave / mptcp },
        );
    }
    if expected_rounds == SEED_PAIRS.len() {
        let outcome = if flowweave_wins_all {
            "FlowWeave 两场中位均高至少 15%，B 胜出"
        } else if mptcp_wins_all {
            "MPTCP 两场中位均高至少 15%，B 胜出"
        } else {
            "无决定性差异"
        };
        println!("- 预注册正式结论：{outcome}");
    }
}

fn write_a_csv(path: &str, observations: &[AObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "direction,round,line_one_seed,line_two_seed,payload_seed,kernel_release,iproute2_version,path_manager,scheduler,congestion_control,total_duration_ms,failure_after_ms,tls13_exact,strict_certificate_validation,subflows_before_failure,subflows_after_run,tcp_fallback_before_failure,tcp_fallback_after_run,remote_key_before_failure,remote_key_after_run,mptcp_retransmits_before_failure,mptcp_retransmits_after_run,mptcp_bytes_retransmitted_before_failure,mptcp_bytes_retransmitted_after_run,line_one_packets_before_failure,line_two_packets_before_failure,original_connection_reused,recovered_after_failure,data_intact,exchange_complete,continuity_pass,recovery_gap_ms,records_received,records_before_failure,records_after_failure,application_bytes_received,protocol_error,failure_reason,application_connection_open_at_deadline,measurement_timed_out,client_line_one_ipv4_bytes_after_failure,client_line_two_ipv4_bytes_after_failure,server_line_one_ipv4_bytes_after_failure,server_line_two_ipv4_bytes_after_failure,line_one_ipv4_bytes_after_failure,line_two_ipv4_bytes_after_failure,client_line_one_packets_after_failure,client_line_two_packets_after_failure,server_line_one_packets_after_failure,server_line_two_packets_after_failure,infrastructure_pass\n",
    );
    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            report.direction.description().to_owned(),
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            observation.payload_seed.to_string(),
            csv_text(&report.runtime.kernel_release),
            csv_text(&report.runtime.iproute2_version),
            csv_text(&report.runtime.path_manager),
            csv_text(&report.runtime.scheduler),
            csv_text(&report.runtime.congestion_control),
            format!("{:.3}", milliseconds(report.total_duration)),
            format!("{:.3}", milliseconds(report.failure_after)),
            report.tls13_exact.to_string(),
            report.strict_certificate_validation.to_string(),
            report.info_before_failure.subflows_total.to_string(),
            report.info_after_run.subflows_total.to_string(),
            report.info_before_failure.fallback.to_string(),
            report.info_after_run.fallback.to_string(),
            report.info_before_failure.remote_key_received.to_string(),
            report.info_after_run.remote_key_received.to_string(),
            report.info_before_failure.retransmits.to_string(),
            report.info_after_run.retransmits.to_string(),
            report.info_before_failure.bytes_retransmitted.to_string(),
            report.info_after_run.bytes_retransmitted.to_string(),
            report.line_one_packets_before_failure.to_string(),
            report.line_two_packets_before_failure.to_string(),
            report.original_connection_reused.to_string(),
            report.recovered_after_failure.to_string(),
            report.data_intact.to_string(),
            report.exchange_complete.to_string(),
            report.continuity_pass.to_string(),
            report
                .recovery_gap
                .map(|value| format!("{:.3}", milliseconds(value)))
                .unwrap_or_default(),
            report.records_received.to_string(),
            report.records_before_failure.to_string(),
            report.records_after_failure.to_string(),
            report.application_bytes_received.to_string(),
            csv_text(report.protocol_error.as_deref().unwrap_or_default()),
            csv_text(report.failure_reason.as_deref().unwrap_or_default()),
            report.application_connection_open_at_deadline.to_string(),
            report.measurement_timed_out.to_string(),
            report.client_line_one_ipv4_bytes_after_failure.to_string(),
            report.client_line_two_ipv4_bytes_after_failure.to_string(),
            report.server_line_one_ipv4_bytes_after_failure.to_string(),
            report.server_line_two_ipv4_bytes_after_failure.to_string(),
            report.line_one_ipv4_bytes_after_failure().to_string(),
            report.line_two_ipv4_bytes_after_failure().to_string(),
            report.client_line_one_packets_after_failure.to_string(),
            report.client_line_two_packets_after_failure.to_string(),
            report.server_line_one_packets_after_failure.to_string(),
            report.server_line_two_packets_after_failure.to_string(),
            report.infrastructure_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }
    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
    Ok(())
}

fn write_b_csv(path: &str, observations: &[BObservation]) -> LabResult<()> {
    let mut csv = String::from(
        "scenario,round,line_one_seed,line_two_seed,payload_seed,kernel_release,iproute2_version,path_manager,scheduler,congestion_control,mode,warmup_ms,measurement_ms,measurement_elapsed_ms,chunk_size_bytes,tls13_exact,strict_certificate_validation,subflows_at_start,subflows_at_end,tcp_fallback_at_start,tcp_fallback_at_end,remote_key_at_start,remote_key_at_end,mptcp_retransmits_at_start,mptcp_retransmits_at_end,mptcp_bytes_retransmitted_at_start,mptcp_bytes_retransmitted_at_end,line_one_packets_before_workload,line_two_packets_before_workload,data_intact,exchange_complete,writer_alive_at_measurement_start,writer_alive_at_measurement_end,records_received_in_window,application_bytes_received_in_window,throughput_mbps,total_records_received,total_application_bytes_received,client_line_one_ipv4_bytes,client_line_two_ipv4_bytes,server_line_one_ipv4_bytes,server_line_two_ipv4_bytes,line_one_ipv4_bytes,line_two_ipv4_bytes,total_ipv4_bytes,ipv4_wire_ratio,line_one_share_percent,line_two_share_percent,client_line_one_packets,client_line_two_packets,server_line_one_packets,server_line_two_packets,infrastructure_pass\n",
    );
    for observation in observations {
        let report = &observation.report;
        let fields = vec![
            observation.scenario.description().to_owned(),
            observation.round.to_string(),
            observation.seeds.line_one.to_string(),
            observation.seeds.line_two.to_string(),
            observation.payload_seed.to_string(),
            csv_text(&report.runtime.kernel_release),
            csv_text(&report.runtime.iproute2_version),
            csv_text(&report.runtime.path_manager),
            csv_text(&report.runtime.scheduler),
            csv_text(&report.runtime.congestion_control),
            report.mode.description().to_owned(),
            report.warmup_duration.as_millis().to_string(),
            report.measurement_duration.as_millis().to_string(),
            format!("{:.3}", milliseconds(report.measurement_elapsed)),
            report.chunk_size.to_string(),
            report.tls13_exact.to_string(),
            report.strict_certificate_validation.to_string(),
            report.info_at_start.subflows_total.to_string(),
            report.info_at_end.subflows_total.to_string(),
            report.info_at_start.fallback.to_string(),
            report.info_at_end.fallback.to_string(),
            report.info_at_start.remote_key_received.to_string(),
            report.info_at_end.remote_key_received.to_string(),
            report.info_at_start.retransmits.to_string(),
            report.info_at_end.retransmits.to_string(),
            report.info_at_start.bytes_retransmitted.to_string(),
            report.info_at_end.bytes_retransmitted.to_string(),
            report.line_one_packets_before_workload.to_string(),
            report.line_two_packets_before_workload.to_string(),
            report.data_intact.to_string(),
            report.exchange_complete.to_string(),
            report.writer_alive_at_measurement_start.to_string(),
            report.writer_alive_at_measurement_end.to_string(),
            report.records_received_in_window.to_string(),
            report.application_bytes_received_in_window.to_string(),
            format!("{:.6}", report.throughput_mbps),
            report.total_records_received.to_string(),
            report.total_application_bytes_received.to_string(),
            report.client_line_one_ipv4_bytes.to_string(),
            report.client_line_two_ipv4_bytes.to_string(),
            report.server_line_one_ipv4_bytes.to_string(),
            report.server_line_two_ipv4_bytes.to_string(),
            report.line_one_ipv4_bytes().to_string(),
            report.line_two_ipv4_bytes().to_string(),
            report.total_ipv4_bytes().to_string(),
            format!("{:.6}", report.ipv4_wire_ratio()),
            format!("{:.6}", report.line_one_share_percent()),
            format!("{:.6}", report.line_two_share_percent()),
            report.client_line_one_packets.to_string(),
            report.client_line_two_packets.to_string(),
            report.server_line_one_packets.to_string(),
            report.server_line_two_packets.to_string(),
            report.infrastructure_pass().to_string(),
        ];
        writeln!(csv, "{}", fields.join(","))?;
    }
    fs::create_dir_all("benchmark-results")?;
    fs::write(path, csv)?;
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
    run_command(
        "tc",
        &[
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
        ],
    )
}

fn print_tc_statistics() -> LabResult<()> {
    let output = Command::new("tc")
        .args(["-s", "qdisc", "show", "dev", "lo"])
        .output()?;
    if !output.status.success() {
        return Err(lab_error(format!(
            "无法读取 MPTCP 网络模拟统计：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    println!();
    println!("内核网络模拟器统计：");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn verify_isolated_environment() -> LabResult<()> {
    if env::var("FLOWWEAVE_MPTCP_LAB").as_deref() != Ok("1") {
        return Err(lab_error(
            "拒绝运行：必须使用 scripts/run_mptcp_comparison.sh",
        ));
    }
    let parent =
        env::var("FLOWWEAVE_PARENT_NETNS").map_err(|_| lab_error("缺少主网络命名空间标识"))?;
    let current = fs::read_link("/proc/self/ns/net")?;
    if current.to_string_lossy() == parent {
        return Err(lab_error("拒绝在主网络命名空间运行 MPTCP 对照"));
    }
    let uid_map = fs::read_to_string("/proc/self/uid_map")?;
    let mapped_root = uid_map
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        == Some("0");
    if !mapped_root {
        return Err(lab_error("MPTCP 对照不是 rootless uid 0 映射环境"));
    }
    Ok(())
}

fn ensure_result_absent(path: &str) -> LabResult<()> {
    if std::path::Path::new(path).exists() {
        return Err(lab_error(format!("拒绝覆盖已有 MPTCP 证据：{path}")));
    }
    Ok(())
}

fn run_command(command: &str, arguments: &[&str]) -> LabResult<()> {
    let output = Command::new(command).args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(lab_error(format!(
        "{command} 命令失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    Some(values[values.len() / 2])
}

fn csv_text(value: &str) -> String {
    value.replace([',', '\n', '\r'], ";")
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

const fn yes_or_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}

fn lab_error(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(message.into()).into()
}
