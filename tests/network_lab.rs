use std::{env, fs, io, process::Command, time::Duration};

use flowweave_lab::{
    DatagramMeasurement, FailoverReport, LabResult, NetworkBenchmarkConfig, NetworkBenchmarkReport,
    PathMode, run_blackhole_failover, run_network_benchmark,
};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "必须通过 scripts/run_netem_lab.sh 在隔离网络命名空间中运行"]
async fn controlled_bad_network_lab() -> LabResult<()> {
    ensure_isolated_network_namespace()?;

    println!();
    println!("FlowWeave / 织流 第二阶段 A：可重复坏网络实验");
    println!("所有网络限制只存在于本次一次性网络命名空间，不会修改真实网卡。");

    println!();
    println!("场景一：两条质量不同、但都可用的线路");
    apply_profiles(
        LinkProfile::new("20ms", "0.1%", "20mbit"),
        LinkProfile::new("80ms", "1%", "20mbit"),
    )?;
    let normal_multipath = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::MultipathAvailable,
        512 * KIB,
        48,
    ))
    .await?;
    print_benchmark(&normal_multipath);

    println!();
    println!("场景二：传输中主线路突然变为 100% 丢包");
    apply_profiles(
        LinkProfile::new("20ms", "0.1%", "20mbit"),
        LinkProfile::new("80ms", "1%", "20mbit"),
    )?;
    let failover = run_blackhole_failover(|| {
        replace_line_profile("1:1", "10:", LinkProfile::new("20ms", "100%", "20mbit"))
    })
    .await?;
    print_failover(&failover);

    println!();
    println!("场景三：线路一丢包 8%，线路二丢包 2%");
    let high_loss_line_one = LinkProfile::new("20ms", "8%", "20mbit");
    let high_loss_line_two = LinkProfile::new("40ms", "2%", "20mbit");
    apply_profiles(high_loss_line_one, high_loss_line_two)?;
    let loss_line_one = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::LineOneOnly,
        384 * KIB,
        72,
    ))
    .await?;
    apply_profiles(high_loss_line_one, high_loss_line_two)?;
    let loss_line_two = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::LineTwoOnly,
        384 * KIB,
        72,
    ))
    .await?;
    apply_profiles(high_loss_line_one, high_loss_line_two)?;
    let loss_multipath = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::MultipathAvailable,
        384 * KIB,
        72,
    ))
    .await?;
    print_benchmark(&loss_line_one);
    print_benchmark(&loss_line_two);
    print_benchmark(&loss_multipath);
    print_comparison(
        "高丢包吞吐量",
        &loss_line_one,
        &loss_line_two,
        &loss_multipath,
    );

    println!();
    println!("场景四：8 Mbit/s 低延迟线路 + 25 Mbit/s 高延迟线路");
    let slow_low_latency = LinkProfile::new("15ms", "0%", "8mbit");
    let fast_high_latency = LinkProfile::new("50ms", "0%", "25mbit");
    apply_profiles(slow_low_latency, fast_high_latency)?;
    let speed_line_one =
        run_network_benchmark(NetworkBenchmarkConfig::new(PathMode::LineOneOnly, MIB, 0)).await?;
    apply_profiles(slow_low_latency, fast_high_latency)?;
    let speed_line_two =
        run_network_benchmark(NetworkBenchmarkConfig::new(PathMode::LineTwoOnly, MIB, 0)).await?;
    apply_profiles(slow_low_latency, fast_high_latency)?;
    let speed_multipath = run_network_benchmark(NetworkBenchmarkConfig::new(
        PathMode::MultipathAvailable,
        MIB,
        0,
    ))
    .await?;
    print_benchmark(&speed_line_one);
    print_benchmark(&speed_line_two);
    print_benchmark(&speed_multipath);
    print_comparison(
        "异构线路吞吐量",
        &speed_line_one,
        &speed_line_two,
        &speed_multipath,
    );

    println!();
    println!("实验结论只代表 NoQ 1.0.1 的当前默认行为，不代表我们已经实现聚合或 FEC。");
    print_tc_statistics()?;
    Ok(())
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

fn apply_profiles(line_one: LinkProfile, line_two: LinkProfile) -> LabResult<()> {
    replace_line_profile("1:1", "10:", line_one)?;
    replace_line_profile("1:2", "20:", line_two)
}

fn replace_line_profile(
    parent: &'static str,
    handle: &'static str,
    profile: LinkProfile,
) -> LabResult<()> {
    let seed = if parent == "1:1" { "1101" } else { "2202" };
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
        seed,
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
        "  流传输：{} 字节，耗时 {:.2} ms，吞吐量 {:.2} Mbit/s",
        report.transfer_size,
        milliseconds(report.transfer_duration),
        report.throughput_mbps
    );
    print_datagrams(&report.datagrams);
    println!(
        "  线路一：发送 {} 字节，丢失 {} 包，最终 RTT {:.2} ms",
        report.line_one.udp_bytes_sent,
        report.line_one.lost_packets,
        milliseconds(report.line_one.final_rtt)
    );
    println!(
        "  线路二：发送 {} 字节，丢失 {} 包，最终 RTT {:.2} ms",
        report.line_two.udp_bytes_sent,
        report.line_two.lost_packets,
        milliseconds(report.line_two.final_rtt)
    );
    println!(
        "  QUIC UDP 总发送 {} 字节，其中应用数据之外约 {} 字节",
        report.total_udp_bytes_sent, report.extra_udp_bytes_sent
    );
    if report.mode == PathMode::MultipathAvailable {
        println!(
            "  两条线路都显著承载流量：{}",
            yes_or_no(report.both_paths_carried_meaningful_traffic())
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
        "{name}对照：最佳单线路 {:.2} Mbit/s，默认多路径 {:.2} Mbit/s（{:.1}%）",
        best_single,
        multipath.throughput_mbps,
        ratio * 100.0
    );
    println!("{name}判断：{conclusion}");
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
