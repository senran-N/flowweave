//! Tests for multipath

use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use bytes::Bytes;
use testresult::TestResult;
use tracing::info;

use crate::{
    ClientConfig, ConnectionId, ConnectionIdGenerator, Endpoint, EndpointConfig, FourTuple,
    LOCAL_CID_COUNT, NetworkChangeHint, PathId, PathStatus, RandomConnectionIdGenerator,
    SendDatagramError, SendDatagramOnPathError, ServerConfig, Side::*, TIMER_GRANULARITY,
    TransportConfig, cid_queue::CidQueue, congestion::NewRenoConfig,
};
use crate::{
    ClosePathError, Dir, Event, PathAbandonReason, PathEvent, ReadError, StreamEvent,
    TransportErrorCode, n0_nat_traversal,
};

use super::util::{
    ConnPair, Inbound, ManyToManyRouting, Pair, Routing, SimpleFirewallRouting, client_config,
    min_opt, server_config, subscribe,
};

const MAX_PATHS: u32 = 3;

fn open_available_second_path(pair: &mut ConnPair) -> Result<PathId, crate::PathError> {
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(pair.routes.public_server_addr()),
        PathStatus::Available,
    )?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}
    Ok(path_id)
}

fn queue_scheduler_test_data(pair: &mut ConnPair) {
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let data = vec![42; 64 * 1024];
    assert_eq!(
        pair.send_stream(Client, stream).write(&data).unwrap(),
        data.len()
    );
}

fn poll_scheduler_data_path(pair: &mut ConnPair, paths: &[PathId]) -> PathId {
    let before = paths
        .iter()
        .map(|path_id| {
            (
                *path_id,
                pair.path_stats(Client, *path_id).unwrap().udp_tx.datagrams,
            )
        })
        .collect::<Vec<_>>();
    let mut buf = Vec::new();
    let _ = pair
        .poll_transmit(Client, NonZeroUsize::MIN, &mut buf)
        .expect("queued STREAM data should produce a transmit");
    let used = before
        .into_iter()
        .filter_map(|(path_id, datagrams)| {
            (pair.path_stats(Client, path_id).unwrap().udp_tx.datagrams > datagrams)
                .then_some(path_id)
        })
        .collect::<Vec<_>>();
    assert_eq!(used.len(), 1, "one transmit must use exactly one path");
    used[0]
}

#[test]
fn default_scheduler_remains_lowest_path_first() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    let second = open_available_second_path(&mut pair)?;
    queue_scheduler_test_data(&mut pair);
    assert_eq!(
        poll_scheduler_data_path(&mut pair, &[PathId::ZERO, second]),
        PathId::ZERO
    );
    assert_eq!(
        poll_scheduler_data_path(&mut pair, &[PathId::ZERO, second]),
        PathId::ZERO
    );
    Ok(())
}

#[test]
fn targeted_datagram_can_use_backup_without_touching_primary() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    let backup = open_available_second_path(&mut pair)?;
    pair.set_path_status(Client, backup, PathStatus::Backup)?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_before = pair.path_stats(Client, backup).unwrap().frame_tx;
    let payload = Bytes::from_static(b"targeted backup datagram");
    pair.datagrams(Client)
        .send_on_path(backup, payload.clone(), false)?;
    pair.drive();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_after = pair.path_stats(Client, backup).unwrap().frame_tx;
    assert_eq!(primary_after.datagram, primary_before.datagram);
    assert_eq!(backup_after.datagram, backup_before.datagram + 1);
    assert_eq!(pair.datagrams(Server).recv(), Some(payload));
    assert_eq!(pair.datagrams(Server).recv(), None);
    Ok(())
}

#[test]
fn same_datagram_can_be_targeted_once_per_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    let second = open_available_second_path(&mut pair)?;

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let second_before = pair.path_stats(Client, second).unwrap().frame_tx;
    let payload = Bytes::from_static(b"one logical payload, two path copies");
    pair.datagrams(Client)
        .send_on_path(PathId::ZERO, payload.clone(), false)?;
    pair.datagrams(Client)
        .send_on_path(second, payload.clone(), false)?;
    pair.drive();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let second_after = pair.path_stats(Client, second).unwrap().frame_tx;
    assert_eq!(primary_after.datagram, primary_before.datagram + 1);
    assert_eq!(second_after.datagram, second_before.datagram + 1);
    assert_eq!(pair.datagrams(Server).recv(), Some(payload.clone()));
    assert_eq!(pair.datagrams(Server).recv(), Some(payload));
    assert_eq!(pair.datagrams(Server).recv(), None);
    Ok(())
}

#[test]
fn ordinary_targeted_datagrams_keep_existing_packet_coalescing() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    let before = pair.path_stats(Client, PathId::ZERO).unwrap();
    pair.datagrams(Client).send_on_path(
        PathId::ZERO,
        Bytes::from_static(b"ordinary one"),
        false,
    )?;
    pair.datagrams(Client).send_on_path(
        PathId::ZERO,
        Bytes::from_static(b"ordinary two"),
        false,
    )?;
    pair.drive();

    let after = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(after.frame_tx.datagram, before.frame_tx.datagram + 2);
    assert_eq!(after.udp_tx.datagrams, before.udp_tx.datagrams + 1);
    Ok(())
}

#[test]
fn separate_targeted_datagrams_use_distinct_udp_packets() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    let before = pair.path_stats(Client, PathId::ZERO).unwrap();
    pair.datagrams(Client).send_on_path(
        PathId::ZERO,
        Bytes::from_static(b"ordinary before boundary"),
        false,
    )?;
    pair.datagrams(Client).send_on_path_separate(
        PathId::ZERO,
        Bytes::from_static(b"separate one"),
        false,
    )?;
    pair.datagrams(Client).send_on_path_separate(
        PathId::ZERO,
        Bytes::from_static(b"separate two"),
        false,
    )?;
    pair.drive();

    let after = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(after.frame_tx.datagram, before.frame_tx.datagram + 3);
    assert_eq!(after.udp_tx.datagrams, before.udp_tx.datagrams + 3);
    Ok(())
}

#[test]
fn targeted_datagram_rejects_unknown_unvalidated_and_closed_paths() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();

    assert_matches!(
        pair.datagrams(Client).send_on_path(
            PathId::MAX,
            Bytes::from_static(b"unknown"),
            false,
        ),
        Err(SendDatagramOnPathError::PathUnavailable(id)) if id == PathId::MAX
    );

    let pending = pair.open_path(
        Client,
        FourTuple {
            local_ip: None,
            remote: SocketAddr::new([9, 8, 7, 6].into(), 5),
        },
        PathStatus::Available,
    )?;
    assert_matches!(
        pair.datagrams(Client).send_on_path(
            pending,
            Bytes::from_static(b"unvalidated"),
            false,
        ),
        Err(SendDatagramOnPathError::PathUnavailable(id)) if id == pending
    );

    let mut closed_pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    let closed = open_available_second_path(&mut closed_pair)?;
    closed_pair.close_path(Client, closed, 0u8.into())?;
    assert_matches!(
        closed_pair.datagrams(Client).send_on_path(
            closed,
            Bytes::from_static(b"closed"),
            false,
        ),
        Err(SendDatagramOnPathError::PathUnavailable(id)) if id == closed
    );
    Ok(())
}

#[test]
fn closing_path_releases_targeted_datagrams_and_backpressure() -> TestResult {
    let _guard = subscribe();
    const SEND_BUFFER_SIZE: usize = 4096;
    let mut builder = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery();
    builder
        .client_transport_cfg
        .datagram_send_buffer_size(SEND_BUFFER_SIZE);
    let mut pair = builder.connect();
    let second = open_available_second_path(&mut pair)?;
    let payload = Bytes::from_static(&[0x5a; 1024]);

    let mut queued = 0usize;
    loop {
        match pair
            .datagrams(Client)
            .send_on_path(second, payload.clone(), false)
        {
            Ok(()) => queued += 1,
            Err(SendDatagramOnPathError::Datagram(SendDatagramError::Blocked(_))) => break,
            Err(error) => panic!("unexpected targeted DATAGRAM error: {error}"),
        }
    }
    assert!(queued > 0);
    assert!(pair.datagrams(Client).send_buffer_space() < SEND_BUFFER_SIZE);

    pair.close_path(Client, second, 0u8.into())?;
    assert_eq!(pair.datagrams(Client).send_buffer_space(), SEND_BUFFER_SIZE);
    let mut saw_unblocked = false;
    while let Some(event) = pair.poll(Client) {
        saw_unblocked |= matches!(event, Event::DatagramsUnblocked);
    }
    assert!(
        saw_unblocked,
        "dropping a blocked path queue must wake the sender"
    );
    Ok(())
}

#[test]
fn targeted_datagram_respects_path_congestion_window() -> TestResult {
    let _guard = subscribe();
    const INITIAL_WINDOW: u64 = 4 * 1200;
    let mut congestion = NewRenoConfig::default();
    congestion.initial_window(INITIAL_WINDOW);
    let mut builder = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery();
    builder
        .client_transport_cfg
        .congestion_controller_factory(Arc::new(congestion));
    let mut pair = builder.connect();
    let backup = open_available_second_path(&mut pair)?;
    pair.set_path_status(Client, backup, PathStatus::Backup)?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    let payload = Bytes::from_static(&[0x7c; 1000]);
    for _ in 0..16 {
        pair.datagrams(Client)
            .send_on_path(backup, payload.clone(), false)?;
    }
    let before = pair.path_stats(Client, backup).unwrap();
    pair.drive_client();
    pair.server.inbound.clear();
    let filled = pair.path_stats(Client, backup).unwrap();
    let mtu = u64::from(pair.current_mtu(Client));
    assert!(filled.frame_tx.datagram > before.frame_tx.datagram);
    assert_eq!(filled.cwnd, INITIAL_WINDOW);
    assert!(
        filled.bytes_in_flight + mtu >= filled.cwnd,
        "test must fill the backup congestion window before checking the boundary"
    );

    let sent_before_blocked_poll = filled.frame_tx.datagram;
    let mut buf = Vec::new();
    assert_matches!(
        pair.poll_transmit(Client, NonZeroUsize::new(10).unwrap(), &mut buf),
        None
    );
    assert_eq!(
        pair.path_stats(Client, backup).unwrap().frame_tx.datagram,
        sent_before_blocked_poll,
        "targeted application data must not be emitted beyond the path congestion window"
    );
    Ok(())
}

fn queue_path_stats_test_data(pair: &mut ConnPair) {
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let data = vec![42; 64 * 1024];
    assert_eq!(
        pair.send_stream(Client, stream).write(&data).unwrap(),
        data.len()
    );
}

fn poll_path_stats_test_data(pair: &mut ConnPair) {
    let mut buf = Vec::new();
    let _transmit = pair
        .poll_transmit(Client, NonZeroUsize::MIN, &mut buf)
        .expect("queued stream data should produce a transmit");
}

fn with_port_offset(mut addr: SocketAddr, offset: u16) -> SocketAddr {
    addr.set_port(addr.port().checked_add(offset).unwrap());
    addr
}

fn recovery_pair(
    pto_reinjection: bool,
    abandon_reinjection: bool,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        pto_reinjection,
        abandon_reinjection,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
}

fn recovery_pair_with_ack_progress(
    pto_reinjection: bool,
    abandon_reinjection: bool,
    ack_progress_reinjection: bool,
    ack_escape: bool,
    feedback_handoff: bool,
    feedback_credit_snapshot: bool,
    feedback_probe: bool,
    feedback_evidence_reinjection: bool,
    stream_obligation_progress: bool,
    blocked_credit_handoff: bool,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        pto_reinjection,
        abandon_reinjection,
        ack_progress_reinjection,
        ack_escape,
        feedback_handoff,
        feedback_credit_snapshot,
        feedback_probe,
        feedback_evidence_reinjection,
        stream_obligation_progress,
        blocked_credit_handoff,
        None,
        1,
        false,
        false,
        false,
        false,
        false,
        false,
    )
}

fn recovery_pair_with_ack_progress_service_deadline(
    pto_reinjection: bool,
    abandon_reinjection: bool,
    ack_progress_reinjection: bool,
    ack_escape: bool,
    feedback_handoff: bool,
    feedback_credit_snapshot: bool,
    feedback_probe: bool,
    feedback_evidence_reinjection: bool,
    stream_obligation_progress: bool,
    blocked_credit_handoff: bool,
    service_deadline: Option<Duration>,
    service_recovery_flights: u32,
    fresh_alternative: bool,
    feedback_stability: bool,
    alternative_stability: bool,
    stream_progress: bool,
    feedback_stream_progress_snapshot: bool,
    gap_delivery_watch: bool,
) -> TestResult<(ConnPair, PathId)> {
    let first_client_addr = Pair::CLIENT_ADDR;
    let first_server_addr = Pair::SERVER_ADDR;
    let second_client_addr = with_port_offset(first_client_addr, 1);
    let second_server_addr = with_port_offset(first_server_addr, 1);
    let routes = ManyToManyRouting::simple_symmetric(
        [first_client_addr, second_client_addr],
        [first_server_addr, second_server_addr],
    );

    let mut builder = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .with_routes(routes.into());
    builder
        .client_transport_cfg
        .cross_path_pto_reinjection(pto_reinjection)
        .cross_path_abandon_reinjection(abandon_reinjection)
        .cross_path_ack_progress_reinjection(ack_progress_reinjection)
        .cross_path_ack_progress_stream_obligation(stream_obligation_progress)
        .cross_path_ack_progress_service_deadline(service_deadline)
        .cross_path_ack_progress_service_recovery_flights(service_recovery_flights)
        .cross_path_ack_progress_fresh_alternative(fresh_alternative)
        .cross_path_ack_progress_feedback_stability(feedback_stability)
        .cross_path_ack_progress_alternative_stability(alternative_stability)
        .cross_path_ack_progress_feedback_probe(feedback_probe)
        .cross_path_ack_progress_feedback_evidence_reinjection(feedback_evidence_reinjection)
        .cross_path_ack_escape(ack_escape)
        .cross_path_feedback_handoff(feedback_handoff)
        .cross_path_feedback_credit_snapshot(feedback_credit_snapshot)
        .cross_path_feedback_stream_progress_snapshot(feedback_stream_progress_snapshot)
        .cross_path_blocked_credit_handoff(blocked_credit_handoff)
        .cross_path_stream_progress(stream_progress)
        .stream_gap_watch_rescue(gap_delivery_watch)
        .stream_gap_delivery_watch_rescue(gap_delivery_watch)
        .default_path_max_idle_timeout(Some(Duration::from_secs(60)));
    builder
        .server_transport_cfg
        .cross_path_pto_reinjection(pto_reinjection)
        .cross_path_abandon_reinjection(abandon_reinjection)
        .cross_path_ack_progress_reinjection(ack_progress_reinjection)
        .cross_path_ack_progress_stream_obligation(stream_obligation_progress)
        .cross_path_ack_progress_service_deadline(service_deadline)
        .cross_path_ack_progress_service_recovery_flights(service_recovery_flights)
        .cross_path_ack_progress_fresh_alternative(fresh_alternative)
        .cross_path_ack_progress_feedback_stability(feedback_stability)
        .cross_path_ack_progress_alternative_stability(alternative_stability)
        .cross_path_ack_progress_feedback_probe(feedback_probe)
        .cross_path_ack_progress_feedback_evidence_reinjection(feedback_evidence_reinjection)
        .cross_path_ack_escape(ack_escape)
        .cross_path_feedback_handoff(feedback_handoff)
        .cross_path_feedback_credit_snapshot(feedback_credit_snapshot)
        .cross_path_feedback_stream_progress_snapshot(feedback_stream_progress_snapshot)
        .cross_path_blocked_credit_handoff(blocked_credit_handoff)
        .cross_path_stream_progress(stream_progress)
        .stream_gap_watch_rescue(gap_delivery_watch)
        .stream_gap_delivery_watch_rescue(gap_delivery_watch)
        .default_path_max_idle_timeout(Some(Duration::from_secs(60)));
    let mut pair = builder.connect();

    let backup = pair.open_path(
        Client,
        FourTuple {
            local_ip: Some(second_client_addr.ip()),
            remote: second_server_addr,
        },
        PathStatus::Backup,
    )?;
    pair.drive();

    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    Ok((pair, backup))
}

fn pto_hedge_pair(enabled: bool) -> TestResult<(ConnPair, PathId)> {
    recovery_pair(enabled, false)
}

fn abandon_recovery_pair(enabled: bool) -> TestResult<(ConnPair, PathId)> {
    recovery_pair(false, enabled)
}

fn ack_progress_recovery_pair(enabled: bool) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        false, false, enabled, false, false, false, false, false, false, false,
    )
}

fn stream_obligation_recovery_pair(enabled: bool) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        false, false, true, false, false, false, false, false, enabled, false,
    )
}

fn ack_escape_recovery_pair(enabled: bool) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        false, false, true, enabled, false, false, false, false, false, false,
    )
}

fn feedback_handoff_recovery_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        false, false, true, true, true, false, false, false, false, false,
    )
}

fn full_feedback_handoff_recovery_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        true, true, true, true, true, false, false, false, false, false,
    )
}

fn full_feedback_snapshot_recovery_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        true, true, true, true, true, true, false, false, false, false,
    )
}

fn feedback_probe_recovery_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        false, false, true, true, true, true, true, false, false, false,
    )
}

fn feedback_evidence_recovery_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        false, false, true, true, true, true, true, true, false, false,
    )
}

fn application_progress_recovery_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(true, true, true, true, true, true, true, true, true, true)
}

fn application_progress_deadline_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        1,
        false,
        false,
        false,
        false,
        false,
        false,
    )
}

fn application_progress_version_aware_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        1,
        true,
        false,
        false,
        false,
        false,
        false,
    )
}

fn application_progress_multi_flight_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        3,
        true,
        false,
        false,
        true,
        false,
        false,
    )
}

fn application_progress_stable_multi_flight_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        3,
        true,
        true,
        false,
        true,
        false,
        false,
    )
}

fn application_progress_delivery_watch_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        3,
        true,
        true,
        false,
        true,
        false,
        true,
    )
}

fn application_progress_alternative_stability_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        3,
        true,
        true,
        true,
        true,
        false,
        true,
    )
}

fn application_progress_stream_progress_snapshot_recovery_pair(
    service_deadline: Duration,
) -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress_service_deadline(
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        true,
        Some(service_deadline),
        3,
        true,
        true,
        true,
        true,
        true,
        true,
    )
}

fn pto_ack_escape_pair() -> TestResult<(ConnPair, PathId)> {
    recovery_pair_with_ack_progress(
        true, false, false, true, false, false, false, false, false, false,
    )
}

fn blackhole_primary_path(pair: &mut ConnPair) -> (SocketAddr, SocketAddr) {
    let Routing::ManyToMany(routes) = &mut pair.routes else {
        panic!("PTO hedge tests require many-to-many routing");
    };
    let client_addr = routes.client_addr(0).unwrap();
    let server_addr = routes.server_addr(0).unwrap();
    routes.sim_client_migration(0, |addr| with_port_offset(addr, 100));
    routes.sim_server_migration(0, |addr| with_port_offset(addr, 100));
    (client_addr, server_addr)
}

fn restore_primary_path(pair: &mut ConnPair, client_addr: SocketAddr, server_addr: SocketAddr) {
    let Routing::ManyToMany(routes) = &mut pair.routes else {
        panic!("PTO hedge tests require many-to-many routing");
    };
    routes.sim_client_migration(0, |_| client_addr);
    routes.sim_server_migration(0, |_| server_addr);
}

fn advance_client_to_next_wakeup(pair: &mut ConnPair) {
    let next = pair
        .client
        .next_wakeup()
        .expect("client should retain a loss-detection wakeup");
    pair.time = next;
    pair.drive_client();
}

fn advance_server_to_next_wakeup(pair: &mut ConnPair) {
    let next = pair
        .server
        .next_wakeup()
        .expect("server should retain a loss-detection wakeup");
    pair.time = next;
    pair.drive_server();
}

fn advance_client_until_hedge(pair: &mut ConnPair, path: PathId) {
    for _ in 0..32 {
        if pair.path_stats(Client, path).unwrap().pto_hedges > 0 {
            return;
        }
        advance_client_to_next_wakeup(pair);
    }
    panic!("PTO hedge did not fire within the deterministic step budget");
}

fn advance_client_until_ack_progress_reinjection(pair: &mut ConnPair, path: PathId) {
    for _ in 0..32 {
        if pair
            .path_stats(Client, path)
            .unwrap()
            .ack_progress_reinjections
            > 0
        {
            return;
        }
        advance_client_to_next_wakeup(pair);
    }
    panic!("ACK-progress reinjection did not fire within the deterministic step budget");
}

fn advance_client_until_feedback_probe(pair: &mut ConnPair, path: PathId) {
    for _ in 0..32 {
        if pair
            .path_stats(Client, path)
            .unwrap()
            .ack_progress_feedback_probes
            > 0
        {
            return;
        }
        advance_client_to_next_wakeup(pair);
    }
    panic!("ACK-progress feedback probe did not fire within the deterministic step budget");
}

fn advance_client_until_probe(
    pair: &mut ConnPair,
    path: PathId,
    initial_pings: u64,
    initial_immediate_acks: u64,
) {
    for _ in 0..32 {
        let frames = pair.path_stats(Client, path).unwrap().frame_tx;
        if frames.ping > initial_pings || frames.immediate_ack > initial_immediate_acks {
            return;
        }
        advance_client_to_next_wakeup(pair);
    }
    panic!("PTO probe did not fire within the deterministic step budget");
}

fn read_all_stream_data(pair: &mut ConnPair, stream: crate::StreamId) -> Vec<u8> {
    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);
    let mut recv = pair.recv_stream(Server, stream);
    let mut chunks = recv.read(false).unwrap();
    let mut data = Vec::new();
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => data.extend_from_slice(&chunk.bytes),
            Ok(None) => break,
            Err(error) => panic!("failed to read reinjected stream: {error}"),
        }
    }
    let _ = chunks.finalize();
    data
}

fn write_stream_data(pair: &mut ConnPair, stream: crate::StreamId, data: &[u8]) {
    assert_eq!(
        pair.send_stream(Client, stream).write(data).unwrap(),
        data.len()
    );
}

const HEDGE_ACK_MESSAGE: &[u8] = b"duplicate ACK accounting";

struct HedgedStreamCopies {
    pair: ConnPair,
    stream: crate::StreamId,
    original: Vec<Inbound>,
    hedge: Vec<Inbound>,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
}

fn prepare_hedged_stream_copies() -> TestResult<HedgedStreamCopies> {
    let (mut pair, _backup) = pto_hedge_pair(true)?;
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, HEDGE_ACK_MESSAGE);
    pair.send_stream(Client, stream).finish()?;

    pair.drive_client();
    let original = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(
        !original.is_empty(),
        "original STREAM packet was not emitted"
    );

    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    let hedge = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!hedge.is_empty(), "backup STREAM packet was not emitted");

    Ok(HedgedStreamCopies {
        pair,
        stream,
        original,
        hedge,
        client_addr,
        server_addr,
    })
}

fn deliver_inbound_group(pair: &mut ConnPair, packets: Vec<Inbound>) {
    pair.server.inbound.extend(packets);
    for _ in 0..8 {
        pair.drive_server();
        if !pair.client.inbound.is_empty() {
            break;
        }
        let next = pair
            .server
            .next_wakeup()
            .expect("server should retain an ACK wakeup");
        pair.time = next;
    }
    assert!(
        !pair.client.inbound.is_empty(),
        "server did not acknowledge the delivered packet group"
    );
    pair.drive_client();
    pair.server.inbound.clear();
}

fn count_finished_events(pair: &mut ConnPair, stream: crate::StreamId) -> usize {
    let mut count = 0;
    while let Some(event) = pair.poll(Client) {
        if matches!(event, Event::Stream(StreamEvent::Finished { id }) if id == stream) {
            count += 1;
        }
    }
    count
}

fn capture_primary_path_ack(pair: &mut ConnPair) -> TestResult<Vec<Inbound>> {
    pair.ping_path(Client, PathId::ZERO)?;
    pair.drive_client();

    for _ in 0..8 {
        pair.drive_server();
        if !pair.client.inbound.is_empty() {
            break;
        }
        let next = pair
            .server
            .next_wakeup()
            .expect("server should retain an ACK wakeup for the primary ping");
        pair.time = next;
    }

    let ack = pair.client.inbound.drain(..).collect::<Vec<_>>();
    assert!(
        !ack.is_empty(),
        "server did not acknowledge the primary ping"
    );
    pair.server.inbound.clear();
    Ok(ack)
}

fn set_feedback_probe_test_rtts(pair: &mut ConnPair, backup: PathId) {
    pair.conn_mut(Client)
        .set_test_path_rtt(PathId::ZERO, Duration::from_millis(200));
    pair.conn_mut(Client)
        .set_test_path_rtt(backup, Duration::from_millis(20));
}

fn deliver_primary_stream_and_drop_ack(
    pair: &mut ConnPair,
    data: &[u8],
) -> TestResult<crate::StreamId> {
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(pair, stream, data);
    pair.send_stream(Client, stream).finish()?;
    pair.drive_client();
    assert!(
        !pair.server.inbound.is_empty(),
        "the original primary STREAM packet must reach the server"
    );

    for _ in 0..8 {
        pair.drive_server();
        if !pair.client.inbound.is_empty() {
            break;
        }
        let next = pair
            .server
            .next_wakeup()
            .expect("server should retain an ACK wakeup for the primary STREAM packet");
        pair.time = next;
    }
    assert!(
        !pair.client.inbound.is_empty(),
        "the server must generate a primary PATH_ACK before it is dropped"
    );
    pair.client.inbound.clear();
    pair.server.inbound.clear();
    Ok(stream)
}

fn deliver_primary_prefix_and_drop_ack(
    pair: &mut ConnPair,
    prefix: &[u8],
) -> TestResult<crate::StreamId> {
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(pair, stream, prefix);
    pair.drive_client();
    assert!(
        !pair.server.inbound.is_empty(),
        "the known prefix must reach the server before the suffix is blackholed"
    );

    for _ in 0..8 {
        pair.drive_server();
        if !pair.client.inbound.is_empty() {
            break;
        }
        let next = pair
            .server
            .next_wakeup()
            .expect("server should retain an ACK wakeup for the known prefix");
        pair.time = next;
    }
    assert!(
        !pair.client.inbound.is_empty(),
        "the server must acknowledge the known prefix before that ACK is dropped"
    );
    pair.client.inbound.clear();
    pair.server.inbound.clear();
    Ok(stream)
}

#[test]
fn cross_path_pto_reinjection_is_disabled_by_default() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(false)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"default off");
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    advance_client_until_probe(
        &mut pair,
        PathId::ZERO,
        primary_before.frame_tx.ping,
        primary_before.frame_tx.immediate_ack,
    );

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after.pto_hedges, 0);
    assert_eq!(primary_after.pto_hedge_bytes, 0);
    assert_eq!(
        backup_after.frame_tx.stream_retransmit_bytes,
        backup_before.frame_tx.stream_retransmit_bytes
    );
    Ok(())
}

#[test]
fn cross_path_ack_progress_reinjection_is_disabled_by_default() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_progress_recovery_pair(false)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"ACK progress default off");
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    assert!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO)
            .is_none()
    );
    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert!(!primary.ack_progress_recovery_timer_armed);
    assert_eq!(primary.ack_progress_recovery_timeouts, 0);
    assert_eq!(primary.ack_progress_reinjections, 0);
    assert_eq!(
        backup_after.frame_tx.stream_retransmit_bytes,
        backup_before.frame_tx.stream_retransmit_bytes
    );
    Ok(())
}

#[test]
fn ack_escape_is_disabled_without_its_explicit_switch() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_escape_recovery_pair(false)?;
    let _stream = deliver_primary_stream_and_drop_ack(&mut pair, b"ACK escape default off")?;
    let client_backup_before = pair.path_stats(Client, backup).unwrap().frame_tx;
    let server_backup_before = pair.path_stats(Server, backup).unwrap().frame_tx;

    blackhole_primary_path(&mut pair);
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);
    assert_eq!(
        pair.path_stats(Client, backup)
            .unwrap()
            .frame_tx
            .path_ack_escape_requests,
        client_backup_before.path_ack_escape_requests,
    );

    pair.drive_server();
    let server_backup_after = pair.path_stats(Server, backup).unwrap().frame_tx;
    assert_eq!(
        server_backup_after.path_ack_escape_acks,
        server_backup_before.path_ack_escape_acks,
    );
    assert_eq!(
        server_backup_after.path_acks_cross_path,
        server_backup_before.path_acks_cross_path,
    );
    assert!(pair.path_status(Client, PathId::ZERO).is_ok());
    Ok(())
}

#[test]
fn ack_progress_recovery_returns_primary_ack_on_backup_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_escape_recovery_pair(true)?;
    let stream = deliver_primary_stream_and_drop_ack(&mut pair, b"bounded ACK escape")?;
    let client_backup_before = pair.path_stats(Client, backup).unwrap().frame_tx;
    let server_backup_before = pair.path_stats(Server, backup).unwrap().frame_tx;

    blackhole_primary_path(&mut pair);
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);
    let client_backup_after = pair.path_stats(Client, backup).unwrap().frame_tx;
    assert_eq!(
        client_backup_after.path_ack_escape_requests,
        client_backup_before.path_ack_escape_requests + 1,
    );
    assert!(
        client_backup_after.immediate_ack > client_backup_before.immediate_ack,
        "the recovery packet on the backup path must request immediate feedback"
    );

    pair.drive_server();
    let server_backup_after = pair.path_stats(Server, backup).unwrap().frame_tx;
    assert_eq!(
        server_backup_after.path_ack_escape_acks,
        server_backup_before.path_ack_escape_acks + 1,
    );
    assert!(
        server_backup_after.path_acks_cross_path > server_backup_before.path_acks_cross_path,
        "the still-open primary path must be cumulatively acknowledged over the backup"
    );
    assert_eq!(
        pair.path_status(Server, PathId::ZERO)?,
        PathStatus::Available,
        "the historical ACK-escape variant must not change path scheduling"
    );
    assert_eq!(
        pair.path_status(Server, backup)?,
        PathStatus::Available,
        "the passive peer keeps both paths available until the handoff switch is enabled"
    );
    assert!(pair.path_status(Client, PathId::ZERO).is_ok());

    pair.drive_client();
    assert_eq!(count_finished_events(&mut pair, stream), 1);
    assert_eq!(pair.streams(Client).send_streams(), 0);
    Ok(())
}

#[test]
fn recovery_feedback_handoff_routes_stream_credit_on_backup() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_handoff_recovery_pair()?;
    let recovered_stream =
        deliver_primary_stream_and_drop_ack(&mut pair, b"feedback handoff trigger")?;

    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);
    pair.drive_server();

    assert_eq!(pair.path_status(Server, PathId::ZERO)?, PathStatus::Backup);
    assert_eq!(pair.path_status(Server, backup)?, PathStatus::Available);

    pair.drive_client();
    assert_eq!(
        read_all_stream_data(&mut pair, recovered_stream),
        b"feedback handoff trigger"
    );
    pair.drive();

    let primary_before = pair.path_stats(Server, PathId::ZERO).unwrap().frame_tx;
    let backup_before = pair.path_stats(Server, backup).unwrap().frame_tx;

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let data = vec![0x5a; 200_000];
    write_stream_data(&mut pair, stream, &data);
    pair.drive();

    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);
    let mut receive = pair.recv_stream(Server, stream);
    let mut chunks = receive.read(false)?;
    let mut read = 0usize;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => read += chunk.bytes.len(),
            Err(ReadError::Blocked) => break,
            Ok(None) => panic!("unfinished stream unexpectedly reached FIN"),
            Err(error) => panic!("failed reading flow-control test stream: {error}"),
        }
    }
    let flow_control_update = chunks.finalize();
    assert_eq!(read, data.len());
    assert!(
        flow_control_update.should_transmit(),
        "reading more than one eighth of the stream window must queue MAX_STREAM_DATA"
    );

    pair.drive_server();
    let primary_after = pair.path_stats(Server, PathId::ZERO).unwrap().frame_tx;
    let backup_after = pair.path_stats(Server, backup).unwrap().frame_tx;
    assert_eq!(
        primary_after.max_stream_data, primary_before.max_stream_data,
        "the blackholed primary must not consume the stream-credit update"
    );
    assert!(
        backup_after.max_stream_data > backup_before.max_stream_data,
        "the promoted recovery path must carry MAX_STREAM_DATA"
    );

    restore_primary_path(&mut pair, client_addr, server_addr);
    pair.ping_path(Client, PathId::ZERO)?;
    pair.conn_mut(Client).immediate_ack(PathId::ZERO);
    pair.drive();
    assert_eq!(
        pair.path_status(Server, PathId::ZERO)?,
        PathStatus::Available,
        "a successful recovery probe must restore the previous primary status"
    );
    assert_eq!(
        pair.path_status(Server, backup)?,
        PathStatus::Available,
        "a successful recovery probe must restore every previous local status"
    );
    Ok(())
}

#[test]
fn stale_stream_data_blocked_reissues_credit_on_its_arrival_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = application_progress_recovery_pair()?;
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let initial = vec![0x41; 200_000];
    write_stream_data(&mut pair, stream, &initial);
    pair.drive();

    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);
    let mut receive = pair.recv_stream(Server, stream);
    let mut chunks = receive.read(false)?;
    let mut read = 0usize;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => read += chunk.bytes.len(),
            Err(ReadError::Blocked) => break,
            Ok(None) => panic!("unfinished credit-escape stream unexpectedly reached FIN"),
            Err(error) => panic!("failed reading credit-escape setup data: {error}"),
        }
    }
    assert_eq!(read, initial.len());
    assert!(chunks.finalize().should_transmit());

    let server_primary_before = pair.path_stats(Server, PathId::ZERO).unwrap();
    let server_backup_before = pair.path_stats(Server, backup).unwrap();
    pair.drive_server();
    let server_primary_with_credit = pair.path_stats(Server, PathId::ZERO).unwrap();
    assert!(
        server_primary_with_credit.frame_tx.max_stream_data
            > server_primary_before.frame_tx.max_stream_data,
        "the stale-credit counterexample requires MAX_STREAM_DATA on the old primary"
    );
    assert_eq!(
        pair.path_stats(Server, backup)
            .unwrap()
            .frame_tx
            .max_stream_data,
        server_backup_before.frame_tx.max_stream_data
    );
    pair.client.inbound.clear();

    blackhole_primary_path(&mut pair);
    pair.set_path_status(Client, PathId::ZERO, PathStatus::Backup)?;
    pair.set_path_status(Client, backup, PathStatus::Available)?;

    let fill_old_limit = vec![0x52; 2_000_000];
    let written = pair
        .send_stream(Client, stream)
        .write(&fill_old_limit)
        .expect("the sender should fill its last known stream credit");
    assert!(written > 0 && written < fill_old_limit.len());
    pair.drive_client();
    assert_eq!(
        pair.send_stream(Client, stream).write(b"still blocked"),
        Err(crate::WriteError::Blocked)
    );

    let backup_before_blocked = pair.path_stats(Server, backup).unwrap();
    // The first backup-path flight fills the congestion window. Let its ACK return before
    // expecting the congestion-controlled STREAM_DATA_BLOCKED signal to leave the sender.
    pair.drive_server();
    pair.drive_client();
    pair.drive_server();
    let backup_after_blocked = pair.path_stats(Server, backup).unwrap();
    let held_credit_response = pair.client.inbound.drain(..).collect::<Vec<_>>();
    assert!(
        !held_credit_response.is_empty(),
        "the first blocked signal must produce a response to hold in flight"
    );
    assert!(
        backup_after_blocked.blocked_credit_handoffs
            > backup_before_blocked.blocked_credit_handoffs
    );
    assert!(
        backup_after_blocked.blocked_credit_max_stream_data_requeues
            > backup_before_blocked.blocked_credit_max_stream_data_requeues
    );
    assert!(
        backup_after_blocked.frame_tx.max_stream_data
            > backup_before_blocked.frame_tx.max_stream_data,
        "the arrival path of stale STREAM_DATA_BLOCKED must carry the latest credit"
    );
    assert_eq!(pair.path_status(Server, PathId::ZERO)?, PathStatus::Backup);
    assert_eq!(pair.path_status(Server, backup)?, PathStatus::Available);

    assert_eq!(
        pair.send_stream(Client, stream)
            .write(b"still blocked again"),
        Err(crate::WriteError::Blocked)
    );
    pair.drive_client();
    pair.drive_server();
    let backup_after_duplicate = pair.path_stats(Server, backup).unwrap();
    assert_eq!(
        backup_after_duplicate.blocked_credit_handoffs,
        backup_after_blocked.blocked_credit_handoffs,
        "a credit response already in flight on this path must absorb duplicate BLOCKED signals"
    );
    assert_eq!(
        backup_after_duplicate.frame_tx.max_stream_data,
        backup_after_blocked.frame_tx.max_stream_data,
        "normal loss recovery owns an in-flight MAX_STREAM_DATA; do not create parallel copies"
    );

    pair.client.inbound.extend(held_credit_response);
    pair.drive_client();
    assert_eq!(pair.send_stream(Client, stream).write(b"u"), Ok(1));
    Ok(())
}

#[test]
fn blocked_credit_handoff_rejects_an_unvalidated_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = application_progress_recovery_pair()?;
    assert!(
        pair.conn(Client).blocked_credit_handoff_eligible(backup),
        "the established backup is the positive control"
    );

    let unvalidated = pair.open_path(
        Client,
        FourTuple {
            remote: SocketAddr::new([9, 8, 7, 6].into(), 5),
            local_ip: None,
        },
        PathStatus::Available,
    )?;
    assert!(
        !pair
            .conn(Client)
            .blocked_credit_handoff_eligible(unvalidated),
        "authenticated flow-control state must not be reflected onto an unvalidated path"
    );
    Ok(())
}

struct InFlightCreditHandoff {
    pair: ConnPair,
    backup: PathId,
    stream: crate::StreamId,
    backup_max_stream_data_before: u64,
}

fn prepare_in_flight_credit_handoff(snapshot: bool) -> TestResult<InFlightCreditHandoff> {
    let (mut pair, backup) = if snapshot {
        full_feedback_snapshot_recovery_pair()?
    } else {
        full_feedback_handoff_recovery_pair()?
    };
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let first = vec![0x41; 200_000];
    write_stream_data(&mut pair, stream, &first);
    pair.drive();

    const UNACKED_TAIL: &[u8] = b"keep one primary packet outstanding";
    write_stream_data(&mut pair, stream, UNACKED_TAIL);
    pair.drive_client();
    assert!(
        !pair.server.inbound.is_empty(),
        "the primary must carry the initial stream range"
    );
    pair.drive_server();
    pair.client.inbound.clear();

    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);
    let mut receive = pair.recv_stream(Server, stream);
    let mut chunks = receive.read(false)?;
    let mut read = 0usize;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => read += chunk.bytes.len(),
            Err(ReadError::Blocked) => break,
            Ok(None) => panic!("unfinished handoff stream unexpectedly reached FIN"),
            Err(error) => panic!("failed reading pre-handoff stream credit: {error}"),
        }
    }
    let update = chunks.finalize();
    assert_eq!(read, first.len() + UNACKED_TAIL.len());
    assert!(update.should_transmit());

    let primary_before = pair.path_stats(Server, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Server, backup).unwrap();
    pair.drive_server();
    let primary_with_credit = pair.path_stats(Server, PathId::ZERO).unwrap();
    assert!(
        primary_with_credit.frame_tx.max_stream_data > primary_before.frame_tx.max_stream_data,
        "the transition counterexample requires MAX_STREAM_DATA to be sent on the old primary"
    );
    assert!(primary_with_credit.tracked_max_stream_data_packets > 0);
    assert_eq!(
        pair.path_stats(Server, backup)
            .unwrap()
            .frame_tx
            .max_stream_data,
        backup_before.frame_tx.max_stream_data,
    );
    pair.client.inbound.clear();

    blackhole_primary_path(&mut pair);
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    pair.drive_server();
    assert_eq!(pair.path_status(Server, PathId::ZERO)?, PathStatus::Backup);
    assert_eq!(pair.path_status(Server, backup)?, PathStatus::Available);

    Ok(InFlightCreditHandoff {
        pair,
        backup,
        stream,
        backup_max_stream_data_before: backup_before.frame_tx.max_stream_data,
    })
}

#[test]
fn historical_feedback_handoff_does_not_snapshot_in_flight_credit() -> TestResult {
    let _guard = subscribe();
    let mut prepared = prepare_in_flight_credit_handoff(false)?;
    assert_eq!(
        prepared
            .pair
            .path_stats(Server, prepared.backup)
            .unwrap()
            .frame_tx
            .max_stream_data,
        prepared.backup_max_stream_data_before,
        "the earlier failed candidate must remain reproducible"
    );
    Ok(())
}

#[test]
fn recovery_feedback_handoff_reissues_credit_already_in_flight_on_primary() -> TestResult {
    let _guard = subscribe();
    let InFlightCreditHandoff {
        mut pair,
        backup,
        stream,
        backup_max_stream_data_before,
    } = prepare_in_flight_credit_handoff(true)?;

    let backup_after_handoff = pair.path_stats(Server, backup).unwrap();
    assert!(
        backup_after_handoff.frame_tx.max_stream_data > backup_max_stream_data_before,
        "feedback handoff must reissue credit already owned by a packet on the failed path"
    );
    pair.drive_client();

    let second = vec![0x52; 1_200_000];
    write_stream_data(&mut pair, stream, &second);
    Ok(())
}

struct InFlightStreamProgressHandoff {
    pair: ConnPair,
    backup: PathId,
    stream: crate::StreamId,
    consumed: u64,
    backup_stream_progress_before: u64,
}

fn prepare_in_flight_stream_progress_handoff(
    snapshot: bool,
) -> TestResult<InFlightStreamProgressHandoff> {
    let (mut pair, backup) = if snapshot {
        application_progress_stream_progress_snapshot_recovery_pair(Duration::from_secs(1))?
    } else {
        application_progress_alternative_stability_recovery_pair(Duration::from_secs(1))?
    };

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let data = vec![0x73; 8 * 1024];
    write_stream_data(&mut pair, stream, &data);
    pair.drive_client();
    assert!(!pair.server.inbound.is_empty());
    pair.drive_server();

    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);
    let mut receive = pair.recv_stream(Server, stream);
    let mut chunks = receive.read(true)?;
    let mut consumed = 0_u64;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => consumed = consumed.saturating_add(chunk.bytes.len() as u64),
            Err(ReadError::Blocked) => break,
            Ok(None) => panic!("unfinished progress-snapshot stream unexpectedly reached FIN"),
            Err(error) => panic!("failed reading progress-snapshot stream: {error}"),
        }
    }
    assert_eq!(consumed, data.len() as u64);
    assert!(chunks.finalize().should_transmit());

    let primary_before = pair.path_stats(Server, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Server, backup).unwrap();
    pair.drive_server();
    let primary_with_progress = pair.path_stats(Server, PathId::ZERO).unwrap();
    assert_eq!(
        primary_with_progress.frame_tx.stream_progress,
        primary_before.frame_tx.stream_progress + 1,
        "the counterexample requires the newest STREAM_PROGRESS to be owned by the old primary"
    );
    assert_eq!(
        pair.path_stats(Server, backup)
            .unwrap()
            .frame_tx
            .stream_progress,
        backup_before.frame_tx.stream_progress
    );
    pair.client.inbound.clear();

    blackhole_primary_path(&mut pair);
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    pair.drive_server();
    assert_eq!(pair.path_status(Server, PathId::ZERO)?, PathStatus::Backup);
    assert_eq!(pair.path_status(Server, backup)?, PathStatus::Available);

    Ok(InFlightStreamProgressHandoff {
        pair,
        backup,
        stream,
        consumed,
        backup_stream_progress_before: backup_before.frame_tx.stream_progress,
    })
}

#[test]
fn historical_v6_8_does_not_snapshot_in_flight_stream_progress() -> TestResult {
    let _guard = subscribe();
    let mut prepared = prepare_in_flight_stream_progress_handoff(false)?;
    assert_eq!(
        prepared
            .pair
            .path_stats(Server, prepared.backup)
            .unwrap()
            .frame_tx
            .stream_progress,
        prepared.backup_stream_progress_before,
        "v6.8 must remain reproducible without the isolated progress-snapshot switch"
    );
    Ok(())
}

#[test]
fn feedback_handoff_snapshots_in_flight_stream_progress_on_backup() -> TestResult {
    let _guard = subscribe();
    let InFlightStreamProgressHandoff {
        mut pair,
        backup,
        stream,
        consumed,
        backup_stream_progress_before,
    } = prepare_in_flight_stream_progress_handoff(true)?;

    assert!(
        pair.path_stats(Server, backup)
            .unwrap()
            .frame_tx
            .stream_progress
            > backup_stream_progress_before,
        "handoff must reissue the maximum in-flight STREAM_PROGRESS on the healthy path"
    );
    pair.drive_client();

    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(backup_after.stream_progress_updates, 1);
    assert!(backup_after.stream_progress_acked_bytes <= consumed);
    let stream_stats = pair
        .conn_mut(Client)
        .stats()
        .streams
        .into_iter()
        .find(|stats| stats.id == stream)
        .unwrap();
    assert_eq!(stream_stats.send_fully_acked_offset, Some(consumed));
    assert_eq!(stream_stats.send_unacknowledged_bytes, Some(0));
    assert_eq!(stream_stats.send_retransmit_bytes, Some(0));
    Ok(())
}

#[test]
fn recovery_backup_pto_repairs_a_lost_stream_tail_after_primary_closes() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = full_feedback_handoff_recovery_pair()?;
    let recovered_stream =
        deliver_primary_stream_and_drop_ack(&mut pair, b"feedback handoff before tail loss")?;

    blackhole_primary_path(&mut pair);
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    pair.drive_server();
    pair.drive_client();
    assert_eq!(
        read_all_stream_data(&mut pair, recovered_stream),
        b"feedback handoff before tail loss"
    );
    pair.drive_server();
    pair.drive_client();

    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    assert_eq!(
        pair.path_status(Client, backup)?,
        PathStatus::Backup,
        "NoQ reports the peer's PATH_STATUS separately; the sole remaining backup is still usable"
    );

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    const TAIL: &[u8] = b"the healthy backup must recover its own lost tail";
    write_stream_data(&mut pair, stream, TAIL);
    pair.send_stream(Client, stream).finish()?;
    pair.drive_client();
    assert!(
        !pair.server.inbound.is_empty(),
        "the backup must emit the tail packet before the test drops it"
    );
    pair.server.inbound.clear();

    let armed = pair.path_stats(Client, backup).unwrap();
    assert!(armed.ack_eliciting_packets_in_flight > 0);
    assert!(armed.loss_detection_timer_armed);

    let pto_before = pair.path_stats(Client, backup).unwrap().pto_timeouts;
    pair.time += Duration::from_secs(1);
    pair.drive_client();
    assert!(
        pair.path_stats(Client, backup).unwrap().pto_timeouts > pto_before,
        "a lost tail on the sole healthy path must fire that path's PTO"
    );

    pair.drive_server();
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    assert_eq!(read_all_stream_data(&mut pair, stream), TAIL);
    Ok(())
}

#[test]
fn recovery_backup_pto_repairs_a_lost_reverse_response_after_handoff() -> TestResult {
    let _guard = subscribe();
    let InFlightCreditHandoff {
        mut pair, backup, ..
    } = prepare_in_flight_credit_handoff(true)?;
    pair.drive_client();

    let stream = pair.streams(Client).open(Dir::Bi).unwrap();
    const REQUEST: &[u8] = b"request after feedback handoff";
    write_stream_data(&mut pair, stream, REQUEST);
    pair.send_stream(Client, stream).finish()?;
    pair.drive();

    assert_matches!(pair.streams(Server).accept(Dir::Bi), Some(id) if id == stream);
    let mut request = pair.recv_stream(Server, stream);
    let mut chunks = request.read(true)?;
    let mut received = Vec::new();
    while let Some(chunk) = chunks.next(usize::MAX)? {
        received.extend_from_slice(&chunk.bytes);
    }
    let _ = chunks.finalize();
    assert_eq!(received, REQUEST);

    const RESPONSE: &[u8] = b"small final validation response";
    assert_eq!(
        pair.send_stream(Server, stream).write(RESPONSE)?,
        RESPONSE.len()
    );
    pair.send_stream(Server, stream).finish()?;
    pair.drive_server();
    assert!(
        !pair.client.inbound.is_empty(),
        "the promoted backup must emit the reverse response"
    );
    pair.client.inbound.clear();

    let lost = pair.path_stats(Server, backup).unwrap();
    assert!(lost.ack_eliciting_packets_in_flight > 0);
    assert!(lost.loss_detection_timer_armed);
    for _ in 0..32 {
        if pair.path_stats(Server, backup).unwrap().pto_timeouts > lost.pto_timeouts {
            break;
        }
        advance_server_to_next_wakeup(&mut pair);
    }
    assert!(
        pair.path_stats(Server, backup).unwrap().pto_timeouts > lost.pto_timeouts,
        "the backup must run PTO for a lost reverse response"
    );

    pair.drive_client();
    pair.drive_server();
    pair.drive_client();
    let mut response = pair.recv_stream(Client, stream);
    let mut chunks = response.read(true)?;
    let mut received = Vec::new();
    while let Some(chunk) = chunks.next(usize::MAX)? {
        received.extend_from_slice(&chunk.bytes);
    }
    let _ = chunks.finalize();
    assert_eq!(received, RESPONSE);
    Ok(())
}

#[test]
fn recovery_backup_pto_repairs_a_lost_reverse_only_fin_after_handoff() -> TestResult {
    let _guard = subscribe();
    let InFlightCreditHandoff {
        mut pair, backup, ..
    } = prepare_in_flight_credit_handoff(true)?;
    pair.drive_client();

    let stream = pair.streams(Client).open(Dir::Bi).unwrap();
    write_stream_data(&mut pair, stream, b"request before split response");
    pair.send_stream(Client, stream).finish()?;
    pair.drive();
    assert_matches!(pair.streams(Server).accept(Dir::Bi), Some(id) if id == stream);

    const RESPONSE: &[u8] = b"response bytes arrive before FIN";
    assert_eq!(
        pair.send_stream(Server, stream).write(RESPONSE)?,
        RESPONSE.len()
    );
    pair.drive_server();
    pair.drive_client();
    pair.drive_server();

    pair.send_stream(Server, stream).finish()?;
    pair.drive_server();
    assert!(
        !pair.client.inbound.is_empty(),
        "finishing the reverse stream must emit a pure FIN packet"
    );
    pair.client.inbound.clear();
    let lost_fin = pair.path_stats(Server, backup).unwrap();
    assert!(lost_fin.loss_detection_timer_armed);

    for _ in 0..32 {
        if pair.path_stats(Server, backup).unwrap().pto_timeouts > lost_fin.pto_timeouts {
            break;
        }
        advance_server_to_next_wakeup(&mut pair);
    }
    assert!(
        pair.path_stats(Server, backup).unwrap().pto_timeouts > lost_fin.pto_timeouts,
        "the backup must run PTO for a lost reverse FIN"
    );
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    let mut response = pair.recv_stream(Client, stream);
    let mut chunks = response.read(true)?;
    let mut received = Vec::new();
    while let Some(chunk) = chunks.next(usize::MAX)? {
        received.extend_from_slice(&chunk.bytes);
    }
    let _ = chunks.finalize();
    assert_eq!(received, RESPONSE);
    Ok(())
}

#[test]
fn recovery_feedback_handoff_survives_multiple_stream_windows_after_primary_closes() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_handoff_recovery_pair()?;
    let recovered_stream =
        deliver_primary_stream_and_drop_ack(&mut pair, b"handoff before repeated credits")?;

    blackhole_primary_path(&mut pair);
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);
    pair.drive_server();
    pair.drive_client();
    assert_eq!(
        read_all_stream_data(&mut pair, recovered_stream),
        b"handoff before repeated credits"
    );
    pair.drive_server();
    pair.drive_client();

    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    let primary_before = pair.path_stats(Server, PathId::ZERO).unwrap().frame_tx;
    let backup_before = pair.path_stats(Server, backup).unwrap().frame_tx;
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let mut accepted = false;
    let mut received = 0usize;
    const ROUNDS: usize = 16;
    const BLOCK_SIZE: usize = 200_000;

    for round in 0..ROUNDS {
        let block = vec![round as u8; BLOCK_SIZE];
        write_stream_data(&mut pair, stream, &block);
        pair.drive();

        if !accepted {
            assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);
            accepted = true;
        }
        let mut receive = pair.recv_stream(Server, stream);
        let mut chunks = receive.read(false)?;
        let mut read = 0usize;
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => read += chunk.bytes.len(),
                Err(ReadError::Blocked) => break,
                Ok(None) => panic!("unfinished repeated-credit stream unexpectedly reached FIN"),
                Err(error) => panic!("failed reading repeated-credit stream: {error}"),
            }
        }
        let flow_control_update = chunks.finalize();
        assert_eq!(read, BLOCK_SIZE);
        assert!(flow_control_update.should_transmit());
        received += read;
        pair.drive();
    }

    assert_eq!(received, ROUNDS * BLOCK_SIZE);
    let backup_after = pair.path_stats(Server, backup).unwrap().frame_tx;
    if let Some(primary_after) = pair.path_stats(Server, PathId::ZERO) {
        assert_eq!(
            primary_after.frame_tx.max_stream_data, primary_before.max_stream_data,
            "the closed primary must never consume a later stream-credit update"
        );
    }
    assert!(
        backup_after.max_stream_data >= backup_before.max_stream_data + ROUNDS as u64,
        "every consumed block must refresh stream credit on the healthy backup"
    );
    Ok(())
}

#[test]
fn recovery_backup_pto_retransmits_lost_stream_credit_after_primary_closes() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = full_feedback_handoff_recovery_pair()?;
    let recovered_stream =
        deliver_primary_stream_and_drop_ack(&mut pair, b"handoff before lost stream credit")?;

    blackhole_primary_path(&mut pair);
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    pair.drive_server();
    pair.drive_client();
    assert_eq!(
        read_all_stream_data(&mut pair, recovered_stream),
        b"handoff before lost stream credit"
    );
    pair.drive_server();
    pair.drive_client();

    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let first = vec![0x31; 200_000];
    write_stream_data(&mut pair, stream, &first);
    pair.drive();
    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(id) if id == stream);

    let mut receive = pair.recv_stream(Server, stream);
    let mut chunks = receive.read(false)?;
    let mut read = 0usize;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => read += chunk.bytes.len(),
            Err(ReadError::Blocked) => break,
            Ok(None) => panic!("unfinished lost-credit stream unexpectedly reached FIN"),
            Err(error) => panic!("failed reading lost-credit stream: {error}"),
        }
    }
    let update = chunks.finalize();
    assert_eq!(read, first.len());
    assert!(update.should_transmit());

    let frames_before = pair.path_stats(Server, backup).unwrap().frame_tx;
    pair.drive_server();
    assert!(
        !pair.client.inbound.is_empty(),
        "the receiver must emit the stream-credit update before it is dropped"
    );
    pair.client.inbound.clear();
    let lost_credit = pair.path_stats(Server, backup).unwrap();
    assert!(lost_credit.loss_detection_timer_armed);

    pair.time += Duration::from_secs(1);
    pair.drive_server();
    let after_pto = pair.path_stats(Server, backup).unwrap();
    assert!(after_pto.pto_timeouts > lost_credit.pto_timeouts);
    assert!(
        after_pto.frame_tx.max_stream_data > frames_before.max_stream_data,
        "PTO must retransmit MAX_STREAM_DATA on the healthy backup"
    );
    pair.drive_client();
    pair.drive_server();

    let second = vec![0x52; 1_200_000];
    write_stream_data(&mut pair, stream, &second);
    Ok(())
}

#[test]
fn pto_recovery_also_requests_ack_escape_on_the_backup() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_ack_escape_pair()?;
    let before = pair.path_stats(Client, backup).unwrap().frame_tx;

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"PTO ACK escape");
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);

    let after = pair.path_stats(Client, backup).unwrap().frame_tx;
    assert_eq!(
        after.path_ack_escape_requests,
        before.path_ack_escape_requests + 1,
    );
    assert!(after.immediate_ack > before.immediate_ack);
    Ok(())
}

#[test]
fn ack_progress_recovery_requires_an_alternative_path() -> TestResult {
    let _guard = subscribe();
    let mut builder = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery();
    builder
        .client_transport_cfg
        .cross_path_ack_progress_reinjection(true)
        .default_path_max_idle_timeout(Some(Duration::from_secs(60)));
    let mut pair = builder.connect();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"single path");
    pair.drive_client();
    pair.server.inbound.clear();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert!(!primary.ack_progress_recovery_timer_armed);
    assert!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO)
            .is_none()
    );
    assert_eq!(primary.ack_progress_recovery_timeouts, 0);
    assert_eq!(primary.ack_progress_reinjections, 0);
    Ok(())
}

#[test]
fn first_unacknowledged_stream_packet_arms_ack_progress_timer() -> TestResult {
    let _guard = subscribe();
    let (mut pair, _backup) = ack_progress_recovery_pair(true)?;
    let sent_at = pair.time;

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"start ACK progress epoch");
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    let deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .expect("the first unacknowledged STREAM packet should arm recovery");
    assert!(primary.ack_progress_recovery_timer_armed);
    assert_eq!(deadline, sent_at + primary.pto);
    Ok(())
}

#[test]
fn feedback_probe_reserves_one_alternative_pto_before_full_recovery() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_probe_recovery_pair()?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    let sent_at = pair.time;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    let payload = vec![0x7b; 64 * 1024];
    write_stream_data(&mut pair, stream, &payload);
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let full_deadline = sent_at + primary_before.pto;
    let expected_probe_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .expect("the bounded feedback probe should arm before full recovery");
    assert!(expected_probe_deadline > sent_at);
    assert!(expected_probe_deadline < full_deadline);
    assert!(
        full_deadline.duration_since(expected_probe_deadline) <= backup_before.pto,
        "the probe must be no earlier than the alternative-PTO evidence budget requires"
    );

    pair.time = expected_probe_deadline;
    pair.drive_client();
    let primary_after_probe = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after_probe = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after_probe.ack_progress_feedback_probe_timeouts, 1);
    assert_eq!(primary_after_probe.ack_progress_feedback_probes, 1);
    assert!(primary_after_probe.ack_progress_feedback_probe_bytes > 0);
    assert!(
        primary_after_probe.ack_progress_feedback_probe_bytes
            <= u64::from(primary_after_probe.current_mtu),
        "the evidence-gathering phase must copy at most one previously sent STREAM frame"
    );
    assert_eq!(primary_after_probe.ack_progress_recovery_timeouts, 0);
    assert_eq!(primary_after_probe.ack_progress_reinjections, 0);
    assert!(
        backup_after_probe.frame_tx.stream_retransmit_bytes
            > backup_before.frame_tx.stream_retransmit_bytes
    );
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(full_deadline),
        "the bounded probe must preserve the original complete-recovery deadline"
    );

    // Drop the bounded probe. The original full recovery must still run, even though the
    // suspected-path marker was installed by the earlier stage.
    pair.server.inbound.clear();
    pair.client.inbound.clear();
    pair.time = full_deadline;
    pair.drive_client();
    let primary_after_fallback = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(primary_after_fallback.ack_progress_recovery_timeouts, 1);
    assert_eq!(primary_after_fallback.ack_progress_recovery_attempts, 1);
    assert_eq!(primary_after_fallback.ack_progress_reinjections, 1);
    Ok(())
}

#[test]
fn service_deadline_reserves_alternative_recovery_budget_before_target() -> TestResult {
    let _guard = subscribe();
    let service_deadline = Duration::from_millis(500);
    let (mut pair, backup) = application_progress_deadline_recovery_pair(service_deadline)?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    let sent_at = pair.time;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, &[0x6d; 64 * 1024]);
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let alternative_budget = backup_before.pto + TIMER_GRANULARITY;
    let expected_full_deadline = sent_at + service_deadline.saturating_sub(alternative_budget);
    assert!(expected_full_deadline < sent_at + primary_before.pto);
    assert_eq!(
        primary_before.ack_progress_full_recovery_deadline,
        Some(expected_full_deadline)
    );
    assert_eq!(
        primary_before.ack_progress_service_deadline,
        Some(service_deadline)
    );
    assert_eq!(
        primary_before.ack_progress_alternative_recovery_budget,
        Some(alternative_budget)
    );
    assert!(!primary_before.ack_progress_feedback_probe_staged);

    advance_client_until_feedback_probe(&mut pair, PathId::ZERO);
    let primary_after_probe = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert!(pair.time < expected_full_deadline);
    assert!(primary_after_probe.ack_progress_feedback_probe_staged);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(expected_full_deadline),
        "the staged fallback must preserve the service-budgeted complete-recovery trigger"
    );
    Ok(())
}

#[test]
fn multi_flight_service_budget_reserves_three_alternative_ptos() -> TestResult {
    let _guard = subscribe();
    let service_deadline = Duration::from_secs(1);
    let (mut pair, backup) = application_progress_multi_flight_recovery_pair(service_deadline)?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    pair.time += Duration::from_millis(1);
    pair.ping_path(Client, backup)?;
    pair.drive();
    let sent_at = pair.time;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, &[0x3f; 64 * 1024]);
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    let alternative_budget = backup_before
        .pto
        .saturating_mul(3)
        .saturating_add(TIMER_GRANULARITY);
    assert_eq!(
        primary.ack_progress_alternative_recovery_budget,
        Some(alternative_budget)
    );
    assert_eq!(
        primary.ack_progress_full_recovery_deadline,
        Some(
            (sent_at + primary.pto)
                .min(sent_at + service_deadline.saturating_sub(alternative_budget)),
        )
    );
    Ok(())
}

#[test]
fn feedback_stability_gate_eventually_recovers_a_silent_source() -> TestResult {
    let _guard = subscribe();
    let service_deadline = Duration::from_millis(100);
    let (mut pair, backup) =
        application_progress_stable_multi_flight_recovery_pair(service_deadline)?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    pair.time += Duration::from_millis(1);
    pair.ping_path(Client, backup)?;
    pair.drive();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, &[0x5a; 64 * 1024]);
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    let stability_deadline = pair
        .conn(Client)
        .ack_progress_feedback_stability_deadline_for_test(PathId::ZERO)
        .expect("the isolated v6.6 variant must expose a source-feedback stability floor");
    assert!(
        primary
            .ack_progress_full_recovery_deadline
            .is_some_and(|deadline| deadline <= stability_deadline),
        "the short service target should make feedback stability the active safety floor"
    );
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(stability_deadline)
    );

    pair.time = stability_deadline;
    pair.drive_client();
    let recovered = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(recovered.ack_progress_feedback_probe_timeouts, 0);
    assert_eq!(recovered.ack_progress_feedback_probes, 0);
    assert_eq!(recovered.ack_progress_recovery_timeouts, 1);
    assert_eq!(recovered.ack_progress_recovery_attempts, 1);
    assert_eq!(recovered.ack_progress_reinjections, 1);
    assert!(recovered.ack_progress_reinjected_bytes > 0);
    Ok(())
}

#[test]
fn feedback_stability_gate_blocks_transient_reverse_recovery() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) =
        application_progress_stable_multi_flight_recovery_pair(Duration::from_millis(100))?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    pair.set_path_status(Client, PathId::ZERO, PathStatus::Backup)?;
    pair.set_path_status(Client, backup, PathStatus::Available)?;
    pair.drive();

    deliver_primary_stream_and_drop_ack(
        &mut pair,
        b"healthy secondary data must not recover toward a stale primary",
    )?;
    assert!(
        pair.path_stats(Client, backup)
            .unwrap()
            .ack_progress_stream_frames_in_flight
            > 0,
        "the healthy secondary must retain an ACK-progress obligation for the race"
    );

    // Model the v6.5 inversion: a delayed authenticated packet makes the stale primary appear
    // one tick newer than the healthy secondary, so version ordering alone arms reverse recovery.
    let source_feedback = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, source_feedback);
    pair.time += Duration::from_millis(1);
    let inversion_time = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(PathId::ZERO, inversion_time);
    pair.conn_mut(Client)
        .rearm_ack_progress_recovery_for_test(inversion_time, backup);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_alternative_for_test(backup),
        Some(PathId::ZERO)
    );

    let stale_timer_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(backup)
        .expect("the transient version inversion should arm a guarded timer");
    assert_eq!(
        pair.conn(Client)
            .ack_progress_feedback_stability_deadline_for_test(backup),
        Some(stale_timer_deadline)
    );

    // Refresh the secondary just before the already queued wakeup, then let one delayed primary
    // packet keep the version ordering inverted at that exact instant. The timeout must recheck
    // silence before incrementing counters, probing, or reinjecting.
    pair.time = stale_timer_deadline - Duration::from_millis(1);
    let refreshed_source_time = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, refreshed_source_time);
    pair.time += Duration::from_millis(1);
    let delayed_primary_time = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(PathId::ZERO, delayed_primary_time);
    pair.time += Duration::from_millis(1);
    let stale_wakeup_time = pair.time;
    pair.conn_mut(Client)
        .fire_ack_progress_recovery_timeout_for_test(stale_wakeup_time, backup);

    let guarded = pair.path_stats(Client, backup).unwrap();
    assert_eq!(guarded.ack_progress_feedback_probe_timeouts, 0);
    assert_eq!(guarded.ack_progress_feedback_probes, 0);
    assert_eq!(guarded.ack_progress_recovery_timeouts, 0);
    assert_eq!(guarded.ack_progress_recovery_attempts, 0);
    assert_eq!(guarded.ack_progress_reinjections, 0);
    let refreshed_deadline = pair
        .conn(Client)
        .ack_progress_feedback_stability_deadline_for_test(backup)
        .unwrap();
    assert_eq!(
        pair.conn(Client).ack_progress_recovery_deadline(backup),
        Some(refreshed_deadline)
    );
    assert!(refreshed_deadline > stale_timer_deadline);

    // The next healthy-secondary feedback version becomes newest and removes the reverse target
    // altogether. Production authenticated-packet handling performs this same timer refresh.
    pair.time += Duration::from_millis(1);
    let newest_secondary_time = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, newest_secondary_time);
    pair.conn_mut(Client)
        .rearm_ack_progress_recovery_for_test(newest_secondary_time, backup);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_alternative_for_test(backup),
        None
    );
    assert_eq!(
        pair.conn(Client).ack_progress_recovery_deadline(backup),
        None
    );
    let final_stats = pair.path_stats(Client, backup).unwrap();
    assert_eq!(final_stats.ack_progress_feedback_probes, 0);
    assert_eq!(final_stats.ack_progress_reinjections, 0);
    Ok(())
}

#[test]
fn alternative_stability_gate_rejects_an_isolated_delayed_target_packet() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) =
        application_progress_alternative_stability_recovery_pair(Duration::from_millis(100))?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    pair.set_path_status(Client, PathId::ZERO, PathStatus::Backup)?;
    pair.set_path_status(Client, backup, PathStatus::Available)?;
    pair.drive();

    deliver_primary_stream_and_drop_ack(
        &mut pair,
        b"one delayed primary packet must not prove a continuously healthy recovery target",
    )?;
    assert!(
        pair.path_stats(Client, backup)
            .unwrap()
            .ack_progress_stream_frames_in_flight
            > 0
    );

    let source_feedback = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, source_feedback);
    pair.time += Duration::from_millis(1);
    let isolated_target_feedback = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(PathId::ZERO, isolated_target_feedback);
    pair.conn_mut(Client)
        .rearm_ack_progress_recovery_for_test(isolated_target_feedback, backup);

    assert_eq!(
        pair.conn(Client)
            .ack_progress_alternative_candidate_for_test(backup),
        Some((PathId::ZERO, isolated_target_feedback))
    );
    let source_stability_deadline = pair
        .conn(Client)
        .ack_progress_feedback_stability_deadline_for_test(backup)
        .unwrap();
    let alternative_stability_deadline = pair
        .conn(Client)
        .ack_progress_alternative_stability_deadline_for_test(backup)
        .unwrap();
    assert!(source_stability_deadline < alternative_stability_deadline);
    assert_eq!(
        pair.conn(Client).ack_progress_recovery_deadline(backup),
        Some(alternative_stability_deadline)
    );

    // Source silence is already stable here. Only the new target-continuity gate prevents the
    // isolated delayed primary packet from causing reverse probing or reinjection.
    pair.time = alternative_stability_deadline - Duration::from_millis(1);
    let guarded_wakeup = pair.time;
    pair.conn_mut(Client)
        .fire_ack_progress_recovery_timeout_for_test(guarded_wakeup, backup);
    let guarded = pair.path_stats(Client, backup).unwrap();
    assert_eq!(guarded.ack_progress_feedback_probe_timeouts, 0);
    assert_eq!(guarded.ack_progress_feedback_probes, 0);
    assert_eq!(guarded.ack_progress_recovery_timeouts, 0);
    assert_eq!(guarded.ack_progress_recovery_attempts, 0);
    assert_eq!(guarded.ack_progress_reinjections, 0);
    assert_eq!(
        pair.conn(Client).ack_progress_recovery_deadline(backup),
        Some(alternative_stability_deadline)
    );

    // The healthy secondary refreshes before the candidate interval completes. It becomes newest,
    // which must erase both the candidate and the guarded reverse timer.
    pair.time += Duration::from_millis(1);
    let healthy_source_feedback = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, healthy_source_feedback);
    pair.conn_mut(Client)
        .rearm_ack_progress_recovery_for_test(healthy_source_feedback, backup);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_alternative_for_test(backup),
        None
    );
    assert_eq!(
        pair.conn(Client)
            .ack_progress_alternative_candidate_for_test(backup),
        None
    );
    assert_eq!(
        pair.conn(Client).ack_progress_recovery_deadline(backup),
        None
    );
    let cancelled = pair.path_stats(Client, backup).unwrap();
    assert_eq!(cancelled.ack_progress_feedback_probes, 0);
    assert_eq!(cancelled.ack_progress_reinjections, 0);
    Ok(())
}

#[test]
fn alternative_stability_candidate_does_not_slide_and_recovers_a_blackhole() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) =
        application_progress_alternative_stability_recovery_pair(Duration::from_millis(100))?;
    set_feedback_probe_test_rtts(&mut pair, backup);

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, &[0x68; 64 * 1024]);
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    assert!(
        pair.path_stats(Client, PathId::ZERO)
            .unwrap()
            .ack_progress_stream_frames_in_flight
            > 0
    );

    let source_feedback = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(PathId::ZERO, source_feedback);
    pair.time += Duration::from_millis(1);
    let candidate_since = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, candidate_since);
    pair.conn_mut(Client)
        .rearm_ack_progress_recovery_for_test(candidate_since, PathId::ZERO);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_alternative_for_test(PathId::ZERO),
        Some(backup)
    );
    assert_eq!(
        pair.conn(Client)
            .ack_progress_alternative_candidate_for_test(PathId::ZERO),
        Some((backup, candidate_since))
    );
    let first_candidate_deadline = pair
        .conn(Client)
        .ack_progress_alternative_stability_deadline_for_test(PathId::ZERO)
        .unwrap();

    // More authenticated packets on the same healthy target prove continuity. They must not move
    // candidate_since and turn sustained health into a perpetually receding deadline.
    pair.time += Duration::from_millis(5);
    let later_candidate_feedback = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, later_candidate_feedback);
    pair.conn_mut(Client)
        .rearm_ack_progress_recovery_for_test(later_candidate_feedback, PathId::ZERO);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_alternative_candidate_for_test(PathId::ZERO),
        Some((backup, candidate_since))
    );
    assert_eq!(
        pair.conn(Client)
            .ack_progress_alternative_stability_deadline_for_test(PathId::ZERO),
        Some(first_candidate_deadline)
    );

    let recovery_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .unwrap();
    assert!(recovery_deadline >= first_candidate_deadline);
    pair.time = recovery_deadline;
    pair.conn_mut(Client)
        .fire_ack_progress_recovery_timeout_for_test(recovery_deadline, PathId::ZERO);

    let recovered = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(recovered.ack_progress_feedback_probe_timeouts, 0);
    assert_eq!(recovered.ack_progress_feedback_probes, 0);
    assert_eq!(recovered.ack_progress_recovery_timeouts, 1);
    assert_eq!(recovered.ack_progress_recovery_attempts, 1);
    assert_eq!(recovered.ack_progress_reinjections, 1);
    assert!(recovered.ack_progress_reinjected_bytes > 0);
    Ok(())
}

#[test]
fn delivery_gap_watch_rescues_a_packetized_obligation_only_once() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) =
        application_progress_delivery_watch_recovery_pair(Duration::from_secs(1))?;
    pair.set_path_status(Client, PathId::ZERO, PathStatus::Backup)?;
    pair.set_path_status(Client, backup, PathStatus::Available)?;
    pair.drive();

    let stream = deliver_primary_stream_and_drop_ack(
        &mut pair,
        b"delivery watch must survive retransmit packetization",
    )?;
    assert!(
        pair.path_stats(Client, backup)
            .unwrap()
            .ack_progress_stream_frames_in_flight
            > 0
    );

    // The healthy backup is the newest feedback path, so recovery must stay on-path even while
    // the older primary remains structurally open.
    let primary_version = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(PathId::ZERO, primary_version);
    pair.time += Duration::from_millis(1);
    let backup_version = pair.time;
    pair.conn_mut(Client)
        .set_test_path_last_authenticated_at(backup, backup_version);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_alternative_for_test(backup),
        None
    );

    let before = pair.path_stats(Client, backup).unwrap();
    pair.conn_mut(Client)
        .set_stream_gap_watch_for_test(backup, (stream, 0));
    pair.conn_mut(Client)
        .fire_stream_gap_watch_timeout_for_test(backup_version, backup);
    let armed = pair.path_stats(Client, backup).unwrap();
    assert_eq!(
        armed.stream_gap_rescue_probes,
        before.stream_gap_rescue_probes + 1
    );
    assert!(armed.stream_gap_rescue_bytes > before.stream_gap_rescue_bytes);

    pair.drive_client();
    let sent = pair.path_stats(Client, backup).unwrap();
    assert!(
        sent.frame_tx.stream_retransmit_bytes > before.frame_tx.stream_retransmit_bytes,
        "the delivery rescue must packetize another copy on the healthy path"
    );

    pair.conn_mut(Client)
        .set_stream_gap_watch_for_test(backup, (stream, 0));
    let second_timeout = pair.time;
    pair.conn_mut(Client)
        .fire_stream_gap_watch_timeout_for_test(second_timeout, backup);
    let bounded = pair.path_stats(Client, backup).unwrap();
    assert_eq!(
        bounded.stream_gap_rescue_probes,
        armed.stream_gap_rescue_probes
    );
    assert_eq!(
        bounded.stream_gap_rescue_bytes,
        armed.stream_gap_rescue_bytes
    );
    Ok(())
}

#[test]
fn version_aware_recovery_only_moves_toward_newer_authenticated_feedback() -> TestResult {
    let _guard = subscribe();
    let service_deadline = Duration::from_secs(1);

    let (mut historical, historical_backup) =
        application_progress_deadline_recovery_pair(service_deadline)?;
    historical.time += Duration::from_millis(1);
    historical.ping_path(Client, historical_backup)?;
    historical.drive();
    assert_eq!(
        historical
            .conn(Client)
            .ack_progress_recovery_alternative_for_test(historical_backup),
        Some(PathId::ZERO),
        "the recorded v6.2 behavior must remain reproducible without the freshness switch"
    );

    let (mut version_aware, backup) =
        application_progress_version_aware_recovery_pair(service_deadline)?;
    version_aware.time += Duration::from_millis(1);
    version_aware.ping_path(Client, backup)?;
    version_aware.drive();
    assert_eq!(
        version_aware
            .conn(Client)
            .ack_progress_recovery_alternative_for_test(PathId::ZERO),
        Some(backup),
        "the stale primary may recover toward the path with newer authenticated feedback"
    );
    assert_eq!(
        version_aware
            .conn(Client)
            .ack_progress_recovery_alternative_for_test(backup),
        None,
        "the freshest path must not send deadline-driven recovery back toward a stale route"
    );
    Ok(())
}

#[test]
fn feedback_probe_ack_cancels_full_snapshot_of_already_delivered_data() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_probe_recovery_pair()?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    let stream = deliver_primary_stream_and_drop_ack(
        &mut pair,
        b"one bounded probe should recover cumulative feedback",
    )?;

    blackhole_primary_path(&mut pair);
    advance_client_until_feedback_probe(&mut pair, PathId::ZERO);
    let primary_after_probe = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(primary_after_probe.ack_progress_feedback_probes, 1);
    assert_eq!(primary_after_probe.ack_progress_reinjections, 0);

    pair.drive_server();
    assert_eq!(pair.path_status(Server, PathId::ZERO)?, PathStatus::Backup);
    assert_eq!(pair.path_status(Server, backup)?, PathStatus::Available);
    pair.drive_client();

    assert_eq!(count_finished_events(&mut pair, stream), 1);
    let primary_after_ack = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(primary_after_ack.ack_progress_recovery_timeouts, 0);
    assert_eq!(primary_after_ack.ack_progress_reinjections, 0);
    assert!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO)
            .is_none(),
        "cumulative feedback proving the data delivered must cancel the full fallback"
    );
    Ok(())
}

#[test]
fn feedback_evidence_reinjects_remaining_ranges_before_full_deadline() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_evidence_recovery_pair()?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    let epoch_started = pair.time;
    let stream = deliver_primary_prefix_and_drop_ack(&mut pair, &[0x31; 4 * 1024])?;

    write_stream_data(&mut pair, stream, &[0x52; 64 * 1024]);
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let full_deadline = epoch_started + primary_before.pto;
    advance_client_until_feedback_probe(&mut pair, PathId::ZERO);
    assert!(pair.time < full_deadline);
    let backup_after_probe = pair.path_stats(Client, backup).unwrap();
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(full_deadline)
    );

    pair.drive_server();
    assert!(
        !pair.client.inbound.is_empty(),
        "the bounded probe must return cumulative primary-path evidence on the backup"
    );
    pair.drive_client();

    let primary_after_evidence = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after_evidence = pair.path_stats(Client, backup).unwrap();
    assert!(pair.time < full_deadline);
    assert_eq!(primary_after_evidence.ack_progress_recovery_timeouts, 0);
    assert_eq!(primary_after_evidence.ack_progress_recovery_attempts, 1);
    assert_eq!(primary_after_evidence.ack_progress_reinjections, 1);
    assert!(primary_after_evidence.ack_progress_reinjected_bytes > 0);
    assert!(
        backup_after_evidence.frame_tx.stream_retransmit_bytes
            > backup_after_probe.frame_tx.stream_retransmit_bytes,
        "evidence processing must immediately send the suffix ranges still missing"
    );
    assert!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO)
            .is_none(),
        "evidence-triggered selective recovery supersedes the original full deadline"
    );
    Ok(())
}

#[test]
fn historical_feedback_probe_waits_for_full_deadline_after_partial_evidence() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_probe_recovery_pair()?;
    set_feedback_probe_test_rtts(&mut pair, backup);
    let epoch_started = pair.time;
    let stream = deliver_primary_prefix_and_drop_ack(&mut pair, &[0x31; 4 * 1024])?;

    write_stream_data(&mut pair, stream, &[0x52; 64 * 1024]);
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let full_deadline = epoch_started + pair.path_stats(Client, PathId::ZERO).unwrap().pto;
    advance_client_until_feedback_probe(&mut pair, PathId::ZERO);
    pair.drive_server();
    pair.drive_client();

    let primary_after_evidence = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(primary_after_evidence.ack_progress_recovery_timeouts, 0);
    assert_eq!(primary_after_evidence.ack_progress_recovery_attempts, 0);
    assert_eq!(primary_after_evidence.ack_progress_reinjections, 0);
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(full_deadline),
        "the recorded feedback-probe variant must retain its historical fixed fallback"
    );

    pair.server.inbound.clear();
    pair.client.inbound.clear();
    pair.time = full_deadline;
    pair.drive_client();
    let primary_after_fallback = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(primary_after_fallback.ack_progress_recovery_timeouts, 1);
    assert_eq!(primary_after_fallback.ack_progress_recovery_attempts, 1);
    assert_eq!(primary_after_fallback.ack_progress_reinjections, 1);
    Ok(())
}

#[test]
fn healthy_ack_progress_does_not_emit_feedback_probe() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = feedback_probe_recovery_pair()?;
    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(
        &mut pair,
        stream,
        b"ordinary ACK arrives before evidence guard",
    );
    pair.send_stream(Client, stream).finish()?;
    pair.drive();

    assert_eq!(count_finished_events(&mut pair, stream), 1);
    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(
        primary_after.ack_progress_feedback_probes,
        primary_before.ack_progress_feedback_probes
    );
    assert_eq!(
        backup_after.frame_tx.stream_retransmit_bytes,
        backup_before.frame_tx.stream_retransmit_bytes
    );
    Ok(())
}

#[test]
fn historical_feedback_snapshot_does_not_enable_pre_recovery_probe() -> TestResult {
    let _guard = subscribe();
    let (mut pair, _backup) = full_feedback_snapshot_recovery_pair()?;
    let sent_at = pair.time;

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"historical snapshot deadline");
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(sent_at + primary.pto)
    );
    assert_eq!(primary.ack_progress_feedback_probe_timeouts, 0);
    assert_eq!(primary.ack_progress_feedback_probes, 0);
    Ok(())
}

#[test]
fn later_sends_do_not_postpone_ack_progress_recovery() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_progress_recovery_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"first blocked range");
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let first_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .unwrap();
    let pto = pair.path_stats(Client, PathId::ZERO).unwrap().pto;
    pair.time += pto / 2;

    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, second, b"later send must not slide deadline");
    pair.drive_client();
    let deadline_after_later_send = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .unwrap();
    assert_eq!(deadline_after_later_send, first_deadline);

    pair.time = first_deadline;
    pair.drive_client();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary.pto_timeouts, 0);
    assert_eq!(primary.ack_progress_recovery_timeouts, 1);
    assert_eq!(primary.ack_progress_recovery_attempts, 1);
    assert_eq!(primary.ack_progress_recovery_empty_attempts, 0);
    assert_eq!(primary.ack_progress_reinjections, 1);
    assert!(primary.ack_progress_reinjected_bytes > 0);
    assert!(
        backup_after.frame_tx.stream_retransmit_bytes
            > backup_before.frame_tx.stream_retransmit_bytes
    );
    Ok(())
}

#[test]
fn new_ack_progress_resets_the_recovery_deadline() -> TestResult {
    let _guard = subscribe();
    let (mut pair, _backup) = ack_progress_recovery_pair(true)?;

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"ack this packet");
    pair.drive_client();
    let first_packets = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!first_packets.is_empty());
    let first_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .unwrap();

    let pto = pair.path_stats(Client, PathId::ZERO).unwrap().pto;
    pair.time += pto / 4;
    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, second, b"leave this packet outstanding");
    pair.drive_client();
    let held_second_packets = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!held_second_packets.is_empty());
    assert_eq!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO),
        Some(first_deadline)
    );

    deliver_inbound_group(&mut pair, first_packets);
    let reset_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .expect("the remaining packet should keep the timer armed");
    assert!(reset_deadline > first_deadline);
    assert_eq!(
        reset_deadline,
        pair.time + pair.path_stats(Client, PathId::ZERO).unwrap().pto
    );
    Ok(())
}

fn deliver_later_same_stream_packet_and_observe_deadline(
    stream_obligation_progress: bool,
) -> TestResult<(crate::Instant, crate::Instant)> {
    let (mut pair, _backup) = stream_obligation_recovery_pair(stream_obligation_progress)?;
    let stream = pair.streams(Client).open(Dir::Uni).unwrap();

    write_stream_data(&mut pair, stream, b"hold the oldest stream range");
    pair.drive_client();
    let held_oldest = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!held_oldest.is_empty());
    let first_deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .unwrap();
    if stream_obligation_progress {
        assert_eq!(
            pair.conn(Client)
                .ack_progress_stream_obligation(PathId::ZERO),
            Some((stream, 0))
        );
    }

    let pto = pair.path_stats(Client, PathId::ZERO).unwrap().pto;
    pair.time += pto / 4;
    write_stream_data(&mut pair, stream, b"ack this later range out of order");
    pair.drive_client();
    let later = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!later.is_empty());
    deliver_inbound_group(&mut pair, later);

    let deadline_after_later_ack = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .expect("the held oldest range must keep recovery armed");
    if stream_obligation_progress {
        assert_eq!(
            pair.conn(Client)
                .ack_progress_stream_obligation(PathId::ZERO),
            Some((stream, 0)),
            "an ACK for a later range must not change the retained obligation identity"
        );
    }

    Ok((first_deadline, deadline_after_later_ack))
}

#[test]
fn retained_stream_obligation_ignores_later_packet_ack_progress() -> TestResult {
    let _guard = subscribe();
    let (historical_deadline, historical_after_ack) =
        deliver_later_same_stream_packet_and_observe_deadline(false)?;
    assert!(
        historical_after_ack > historical_deadline,
        "the historical packet-level epoch must remain reproducible"
    );

    let (obligation_deadline, obligation_after_ack) =
        deliver_later_same_stream_packet_and_observe_deadline(true)?;
    assert_eq!(
        obligation_after_ack, obligation_deadline,
        "later packet ACKs must not postpone the same oldest STREAM obligation"
    );
    Ok(())
}

#[test]
fn newly_exposed_stream_obligation_keeps_its_original_send_age() -> TestResult {
    let _guard = subscribe();
    let (mut pair, _backup) = stream_obligation_recovery_pair(true)?;

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"ack the first obligation later");
    pair.drive_client();
    let first_packets = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!first_packets.is_empty());

    let pto = pair.path_stats(Client, PathId::ZERO).unwrap().pto;
    pair.time += pto / 4;
    let second_sent = pair.time;
    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(
        &mut pair,
        second,
        b"this obligation is already aging while hidden",
    );
    pair.drive_client();
    let held_second_packets = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!held_second_packets.is_empty());
    assert_eq!(
        pair.conn(Client)
            .ack_progress_stream_obligation(PathId::ZERO),
        Some((first, 0))
    );

    pair.time += pto / 4;
    deliver_inbound_group(&mut pair, first_packets);

    let current_pto = pair.path_stats(Client, PathId::ZERO).unwrap().pto;
    let deadline = pair
        .conn(Client)
        .ack_progress_recovery_deadline(PathId::ZERO)
        .expect("the already-sent second obligation must keep recovery armed");
    assert_eq!(
        pair.conn(Client)
            .ack_progress_stream_obligation(PathId::ZERO),
        Some((second, 0))
    );
    assert_eq!(
        deadline,
        second_sent + current_pto,
        "revealing an older retained obligation must not restart its age at ACK arrival"
    );
    assert!(deadline < pair.time + current_pto);
    Ok(())
}

#[test]
fn alternative_copy_ack_refreshes_the_original_path_obligation() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = application_progress_recovery_pair()?;
    set_feedback_probe_test_rtts(&mut pair, backup);

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(
        &mut pair,
        stream,
        b"only the alternative-path copy reaches the receiver",
    );
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    assert_eq!(
        pair.conn(Client)
            .ack_progress_stream_obligation(PathId::ZERO),
        Some((stream, 0))
    );

    advance_client_until_feedback_probe(&mut pair, PathId::ZERO);
    pair.drive_server();
    assert!(
        !pair.client.inbound.is_empty(),
        "the alternative-path copy should produce same-path acknowledgment traffic"
    );
    pair.drive_client();

    assert_eq!(
        pair.conn(Client)
            .ack_progress_stream_obligation(PathId::ZERO),
        None,
        "ACKing a retransmitted copy must retire stale original-path obligation metadata"
    );
    assert!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO)
            .is_none()
    );
    Ok(())
}

#[test]
fn one_no_progress_epoch_cannot_amplify_repeatedly() -> TestResult {
    let _guard = subscribe();
    let (mut pair, _backup) = ack_progress_recovery_pair(true)?;
    let payload = vec![42; 128 * 1024];

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.send_stream(Client, stream).write(&payload)?,
        payload.len()
    );
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);
    let after_first = pair.path_stats(Client, PathId::ZERO).unwrap();

    for _ in 0..8 {
        advance_client_to_next_wakeup(&mut pair);
        pair.server.inbound.clear();
        pair.client.inbound.clear();
    }

    let after_retries = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(after_retries.ack_progress_recovery_timeouts, 1);
    assert_eq!(after_retries.ack_progress_recovery_attempts, 1);
    assert_eq!(after_retries.ack_progress_reinjections, 1);
    assert_eq!(
        after_retries.ack_progress_reinjected_bytes,
        after_first.ack_progress_reinjected_bytes
    );
    Ok(())
}

#[test]
fn control_only_flight_does_not_arm_ack_progress_recovery() -> TestResult {
    let _guard = subscribe();
    let (mut pair, _backup) = ack_progress_recovery_pair(true)?;

    pair.ping_path(Client, PathId::ZERO)?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();

    let primary = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert!(!primary.ack_progress_recovery_timer_armed);
    assert!(
        pair.conn(Client)
            .ack_progress_recovery_deadline(PathId::ZERO)
            .is_none()
    );
    assert_eq!(primary.ack_progress_recovery_timeouts, 0);
    Ok(())
}

#[test]
fn cross_path_pto_reinjection_requires_an_alternative_path() -> TestResult {
    let _guard = subscribe();
    let mut builder = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery();
    builder
        .client_transport_cfg
        .cross_path_pto_reinjection(true);
    let mut pair = builder.connect();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"only path");
    pair.send_stream(Client, stream).finish()?;
    pair.drive_client();
    pair.server.inbound.clear();
    let after_send = pair.path_stats(Client, PathId::ZERO).unwrap();
    advance_client_until_probe(
        &mut pair,
        PathId::ZERO,
        after_send.frame_tx.ping,
        after_send.frame_tx.immediate_ack,
    );

    let after = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert_eq!(after.pto_hedges, 0);
    assert_eq!(after.pto_hedge_bytes, 0);
    Ok(())
}

#[test]
fn path_abandon_reinjection_is_disabled_by_default() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = abandon_recovery_pair(false)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"abandon default off");
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive_client();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after.path_abandon_recovery_attempts, 0);
    assert_eq!(primary_after.path_abandon_reinjections, 0);
    assert_eq!(primary_after.path_abandon_reinjected_bytes, 0);
    assert_eq!(
        backup_after.frame_tx.stream_retransmit_bytes,
        backup_before.frame_tx.stream_retransmit_bytes
    );
    Ok(())
}

#[test]
fn path_abandon_reinjects_stream_before_path_state_is_drained() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = abandon_recovery_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();
    const MESSAGE: &[u8] = b"recover before three PTO drain";

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, MESSAGE);
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    let tracked_before_abandon = pair
        .path_stats(Client, PathId::ZERO)
        .unwrap()
        .tracked_ack_eliciting_packets;
    assert!(tracked_before_abandon > 0);

    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive_client();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after.pto_timeouts, 0);
    assert_eq!(primary_after.pto_hedges, 0);
    assert_eq!(primary_after.path_abandon_recovery_attempts, 1);
    assert_eq!(primary_after.path_abandon_recovery_empty_attempts, 0);
    assert_eq!(primary_after.path_abandon_reinjections, 1);
    assert_eq!(
        primary_after.path_abandon_reinjected_bytes,
        MESSAGE.len() as u64
    );
    assert_eq!(
        primary_after.tracked_ack_eliciting_packets, tracked_before_abandon,
        "the original packet-number state must remain available during the drain period"
    );
    assert!(
        backup_after.frame_tx.stream_retransmit_bytes
            > backup_before.frame_tx.stream_retransmit_bytes
    );

    pair.drive_server();
    assert_eq!(read_all_stream_data(&mut pair, stream), MESSAGE);
    Ok(())
}

#[test]
fn first_data_pto_reinjects_stream_on_backup_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();
    const MESSAGE: &[u8] = b"cross-path PTO hedge";

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, MESSAGE);
    pair.send_stream(Client, stream).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after.pto_hedges, 1);
    assert_eq!(primary_after.pto_hedge_bytes, MESSAGE.len() as u64);
    assert!(primary_after.pto_timeouts > 0);
    assert_eq!(primary_after.pto_recovery_attempts, 1);
    assert_eq!(primary_after.pto_recovery_empty_attempts, 0);
    assert!(primary_after.last_pto_recovery_unacked_bytes >= MESSAGE.len() as u64);
    assert!(primary_after.last_pto_recovery_stream_frames > 0);
    assert!(
        backup_after.frame_tx.stream_retransmit_bytes
            > backup_before.frame_tx.stream_retransmit_bytes
    );

    restore_primary_path(&mut pair, client_addr, server_addr);
    pair.drive();
    assert_eq!(read_all_stream_data(&mut pair, stream), MESSAGE);
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));
    Ok(())
}

#[test]
fn repeated_pto_does_not_start_another_hedge_episode() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(true)?;

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, stream, b"one hedge");
    pair.send_stream(Client, stream).finish()?;
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    pair.server.inbound.clear();

    for _ in 0..6 {
        advance_client_to_next_wakeup(&mut pair);
        pair.server.inbound.clear();
    }

    assert_eq!(pair.path_stats(Client, PathId::ZERO).unwrap().pto_hedges, 1);
    assert_eq!(pair.path_stats(Client, backup).unwrap().pto_hedges, 0);
    Ok(())
}

#[test]
fn acknowledged_primary_path_resumes_normal_data_scheduling() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(true)?;

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"before recovery");
    pair.send_stream(Client, first).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);

    restore_primary_path(&mut pair, client_addr, server_addr);
    pair.ping_path(Client, PathId::ZERO)?;
    pair.drive();
    assert_eq!(read_all_stream_data(&mut pair, first), b"before recovery");

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Client, backup).unwrap();
    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, second, b"after recovery");
    pair.send_stream(Client, second).finish()?;
    pair.drive();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert!(primary_after.frame_tx.stream_fresh_bytes > primary_before.frame_tx.stream_fresh_bytes);
    assert_eq!(
        backup_after.frame_tx.stream_fresh_bytes,
        backup_before.frame_tx.stream_fresh_bytes
    );
    assert_eq!(read_all_stream_data(&mut pair, second), b"after recovery");
    assert_eq!(pair.stats(Client).frame_tx.path_abandon, 0);
    Ok(())
}

#[test]
fn stale_pre_hedge_ack_does_not_reactivate_suspected_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(true)?;
    let stale_primary_ack = capture_primary_path_ack(&mut pair)?;

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"trigger hedge");
    pair.send_stream(Client, first).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);
    let hedge_packets = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!hedge_packets.is_empty());

    restore_primary_path(&mut pair, client_addr, server_addr);
    deliver_inbound_group(&mut pair, hedge_packets);
    assert_eq!(count_finished_events(&mut pair, first), 1);
    let _ = blackhole_primary_path(&mut pair);

    pair.client.inbound.extend(stale_primary_ack);
    pair.drive_client();
    pair.server.inbound.clear();

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Client, backup).unwrap();
    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, second, b"must stay on backup");
    pair.drive_client();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(
        primary_after.frame_tx.stream_fresh_bytes, primary_before.frame_tx.stream_fresh_bytes,
        "an ACK for a pre-hedge packet must not reactivate the blackholed primary path"
    );
    assert!(
        backup_after.frame_tx.stream_fresh_bytes > backup_before.frame_tx.stream_fresh_bytes,
        "fresh data should remain on the backup until a post-hedge primary probe is acknowledged"
    );
    Ok(())
}

#[test]
fn stale_pre_ack_progress_ack_does_not_reactivate_suspected_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_progress_recovery_pair(true)?;
    let stale_primary_ack = capture_primary_path_ack(&mut pair)?;

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"trigger ACK-progress recovery");
    pair.send_stream(Client, first).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);
    let reinjected_packets = pair.server.inbound.drain(..).collect::<Vec<_>>();
    assert!(!reinjected_packets.is_empty());

    restore_primary_path(&mut pair, client_addr, server_addr);
    deliver_inbound_group(&mut pair, reinjected_packets);
    assert_eq!(count_finished_events(&mut pair, first), 1);
    let _ = blackhole_primary_path(&mut pair);

    pair.client.inbound.extend(stale_primary_ack);
    pair.drive_client();
    pair.server.inbound.clear();

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Client, backup).unwrap();
    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, second, b"remain on backup after stale ACK");
    pair.drive_client();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(
        primary_after.frame_tx.stream_fresh_bytes, primary_before.frame_tx.stream_fresh_bytes,
        "an ACK below the recovery-probe boundary must not reactivate the primary path"
    );
    assert!(backup_after.frame_tx.stream_fresh_bytes > backup_before.frame_tx.stream_fresh_bytes);
    Ok(())
}

#[test]
fn acknowledged_ack_progress_probe_resumes_normal_data_scheduling() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_progress_recovery_pair(true)?;

    let first = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, first, b"before ACK-progress recovery");
    pair.send_stream(Client, first).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);

    restore_primary_path(&mut pair, client_addr, server_addr);
    pair.ping_path(Client, PathId::ZERO)?;
    pair.drive();
    assert_eq!(
        read_all_stream_data(&mut pair, first),
        b"before ACK-progress recovery"
    );

    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_before = pair.path_stats(Client, backup).unwrap();
    let second = pair.streams(Client).open(Dir::Uni).unwrap();
    write_stream_data(&mut pair, second, b"after ACK-progress recovery");
    pair.send_stream(Client, second).finish()?;
    pair.drive();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert!(primary_after.frame_tx.stream_fresh_bytes > primary_before.frame_tx.stream_fresh_bytes);
    assert_eq!(
        backup_after.frame_tx.stream_fresh_bytes,
        backup_before.frame_tx.stream_fresh_bytes
    );
    assert_eq!(
        read_all_stream_data(&mut pair, second),
        b"after ACK-progress recovery"
    );
    Ok(())
}

#[test]
fn pto_reinjection_respects_backup_congestion_window() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();
    let payload = vec![42; 1024 * 1024];

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.send_stream(Client, stream).write(&payload)?,
        payload.len()
    );
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);

    let backup_after = pair.path_stats(Client, backup).unwrap();
    let fresh =
        backup_after.frame_tx.stream_fresh_bytes - backup_before.frame_tx.stream_fresh_bytes;
    let retransmitted = backup_after.frame_tx.stream_retransmit_bytes
        - backup_before.frame_tx.stream_retransmit_bytes;
    assert!(fresh + retransmitted > 0);
    assert!(
        fresh + retransmitted <= backup_before.cwnd,
        "backup sent {} STREAM bytes with a {} byte congestion window",
        fresh + retransmitted,
        backup_before.cwnd
    );
    Ok(())
}

#[test]
fn ack_progress_reinjection_respects_backup_congestion_window() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_progress_recovery_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();
    let payload = vec![42; 1024 * 1024];

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    assert_eq!(
        pair.send_stream(Client, stream).write(&payload)?,
        payload.len()
    );
    blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);

    let backup_after = pair.path_stats(Client, backup).unwrap();
    let fresh =
        backup_after.frame_tx.stream_fresh_bytes - backup_before.frame_tx.stream_fresh_bytes;
    let retransmitted = backup_after.frame_tx.stream_retransmit_bytes
        - backup_before.frame_tx.stream_retransmit_bytes;
    assert!(fresh + retransmitted > 0);
    assert!(
        fresh + retransmitted <= backup_before.cwnd,
        "backup sent {} STREAM bytes with a {} byte congestion window",
        fresh + retransmitted,
        backup_before.cwnd
    );
    Ok(())
}

#[test]
fn fin_only_pto_reinjection_is_not_mistaken_for_zero_benefit() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    pair.send_stream(Client, stream).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_hedge(&mut pair, PathId::ZERO);

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after.pto_hedges, 1);
    assert_eq!(primary_after.pto_hedge_bytes, 0);
    assert!(
        backup_after.frame_tx.stream > backup_before.frame_tx.stream,
        "the FIN-only STREAM frame must still be sent on the backup path"
    );

    restore_primary_path(&mut pair, client_addr, server_addr);
    pair.drive();
    assert!(read_all_stream_data(&mut pair, stream).is_empty());
    assert_eq!(count_finished_events(&mut pair, stream), 1);
    Ok(())
}

#[test]
fn fin_only_ack_progress_reinjection_is_not_mistaken_for_zero_benefit() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_progress_recovery_pair(true)?;
    let backup_before = pair.path_stats(Client, backup).unwrap();

    let stream = pair.streams(Client).open(Dir::Uni).unwrap();
    pair.send_stream(Client, stream).finish()?;
    let (client_addr, server_addr) = blackhole_primary_path(&mut pair);
    pair.drive_client();
    advance_client_until_ack_progress_reinjection(&mut pair, PathId::ZERO);

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap();
    let backup_after = pair.path_stats(Client, backup).unwrap();
    assert_eq!(primary_after.ack_progress_reinjections, 1);
    assert_eq!(primary_after.ack_progress_reinjected_bytes, 0);
    assert!(
        backup_after.frame_tx.stream > backup_before.frame_tx.stream,
        "the FIN-only STREAM frame must still be sent on the backup path"
    );

    restore_primary_path(&mut pair, client_addr, server_addr);
    pair.drive();
    assert!(read_all_stream_data(&mut pair, stream).is_empty());
    assert_eq!(count_finished_events(&mut pair, stream), 1);
    Ok(())
}

#[test]
fn original_copy_ack_then_hedge_ack_only_finishes_stream_once() -> TestResult {
    let _guard = subscribe();
    let HedgedStreamCopies {
        mut pair,
        stream,
        original,
        hedge,
        client_addr,
        server_addr,
    } = prepare_hedged_stream_copies()?;
    restore_primary_path(&mut pair, client_addr, server_addr);

    deliver_inbound_group(&mut pair, original);
    assert_eq!(count_finished_events(&mut pair, stream), 1);

    deliver_inbound_group(&mut pair, hedge);
    assert_eq!(count_finished_events(&mut pair, stream), 0);
    assert_eq!(pair.streams(Client).send_streams(), 0);
    assert_eq!(read_all_stream_data(&mut pair, stream), HEDGE_ACK_MESSAGE);
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));
    Ok(())
}

#[test]
fn hedge_ack_then_original_copy_ack_only_finishes_stream_once() -> TestResult {
    let _guard = subscribe();
    let HedgedStreamCopies {
        mut pair,
        stream,
        original,
        hedge,
        client_addr,
        server_addr,
    } = prepare_hedged_stream_copies()?;
    restore_primary_path(&mut pair, client_addr, server_addr);

    deliver_inbound_group(&mut pair, hedge);
    assert_eq!(count_finished_events(&mut pair, stream), 1);

    deliver_inbound_group(&mut pair, original);
    assert_eq!(count_finished_events(&mut pair, stream), 0);
    assert_eq!(pair.streams(Client).send_streams(), 0);
    assert_eq!(read_all_stream_data(&mut pair, stream), HEDGE_ACK_MESSAGE);
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));
    Ok(())
}

#[test]
fn path_stats_count_fresh_stream_payload_separately() {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    let before = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    queue_path_stats_test_data(&mut pair);
    poll_path_stats_test_data(&mut pair);
    let after = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;

    assert!(after.stream_fresh_bytes > before.stream_fresh_bytes);
    assert_eq!(
        after.stream_retransmit_bytes,
        before.stream_retransmit_bytes
    );
}

#[test]
fn path_stats_expose_loss_detection_state() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .disable_mtud_discovery()
        .connect();
    let before = pair.path_stats(Client, PathId::ZERO).unwrap();

    pair.ping_path(Client, PathId::ZERO)?;
    pair.drive_client();

    let after = pair.path_stats(Client, PathId::ZERO).unwrap();
    assert!(after.pto > Duration::ZERO);
    assert!(after.latest_ack_eliciting_packet_number > before.latest_ack_eliciting_packet_number);
    assert!(after.bytes_in_flight > 0);
    assert!(after.ack_eliciting_packets_in_flight > 0);
    assert!(after.tracked_sent_packets > 0);
    assert!(after.tracked_ack_eliciting_packets > 0);
    assert!(after.loss_detection_timer_armed);
    Ok(())
}

#[test]
fn non_zero_length_cids() {
    let _guard = subscribe();
    let multipath_transport_cfg = Arc::new(TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(3 as _),
        // Assume a low-latency connection so pacing doesn't interfere with the test
        initial_rtt: Duration::from_millis(10),
        ..TransportConfig::default()
    });
    let server_cfg = Arc::new(ServerConfig {
        transport: multipath_transport_cfg.clone(),
        ..server_config()
    });
    let server = Endpoint::new(Default::default(), Some(server_cfg), true);

    struct ZeroLenCidGenerator;

    impl ConnectionIdGenerator for ZeroLenCidGenerator {
        fn generate_cid(&mut self) -> ConnectionId {
            ConnectionId::new(&[])
        }

        fn cid_len(&self) -> usize {
            0
        }

        fn cid_lifetime(&self) -> Option<std::time::Duration> {
            None
        }
    }

    let mut ep_config = EndpointConfig::default();
    ep_config.cid_generator(Arc::new(|| Box::new(ZeroLenCidGenerator)));
    let client = Endpoint::new(Arc::new(ep_config), None, true);

    let mut pair = Pair::new_from_endpoint(client, server);
    let client_cfg = ClientConfig {
        transport: multipath_transport_cfg,
        ..client_config()
    };
    pair.begin_connect(client_cfg);
    pair.drive();
    let accept_err = pair
        .server
        .accepted
        .take()
        .expect("server didn't try connecting")
        .expect_err("server did not raise error for connection");
    match accept_err {
        crate::ConnectionError::TransportError(error) => {
            assert_eq!(error.code, crate::TransportErrorCode::PROTOCOL_VIOLATION);
        }
        _ => panic!("Not a TransportError"),
    }
}

#[test]
fn path_acks() {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let stats = pair.stats(Client);
    assert!(stats.frame_rx.path_acks > 0);
    assert!(stats.frame_tx.path_acks > 0);
}

#[test]
fn path_ack_prefers_same_feedback_path() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = ack_escape_recovery_pair(true)?;
    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_before = pair.path_stats(Client, backup).unwrap().frame_tx;

    pair.ping_path(Server, backup)?;
    pair.drive();

    let primary_after = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_after = pair.path_stats(Client, backup).unwrap().frame_tx;
    let same_path = primary_after
        .path_acks_same_path
        .saturating_sub(primary_before.path_acks_same_path)
        .saturating_add(
            backup_after
                .path_acks_same_path
                .saturating_sub(backup_before.path_acks_same_path),
        );
    let cross_path = primary_after
        .path_acks_cross_path
        .saturating_sub(primary_before.path_acks_cross_path)
        .saturating_add(
            backup_after
                .path_acks_cross_path
                .saturating_sub(backup_before.path_acks_cross_path),
        );

    assert!(
        same_path > 0,
        "the backup PING must be acknowledged on its own path"
    );
    assert!(
        cross_path == 0,
        "an open backup path must not send its feedback over the primary path"
    );
    Ok(())
}

#[test]
fn path_ack_falls_back_after_acknowledged_path_is_abandoned() -> TestResult {
    let _guard = subscribe();
    let (mut pair, backup) = pto_hedge_pair(false)?;
    let primary_before = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_before = pair.path_stats(Client, backup).unwrap().frame_tx;
    let server_before = pair.stats(Server).frame_rx.path_acks;

    // Receive exactly one ack-eliciting packet on the backup path. It should leave a
    // delayed PATH_ACK pending rather than immediately sending an ACK-only packet.
    pair.ping_path(Server, backup)?;
    pair.drive_server();
    pair.advance_time();
    pair.drive_client();

    let primary_after_receive = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_after_receive = pair.path_stats(Client, backup).unwrap().frame_tx;
    assert_eq!(
        primary_after_receive.path_acks_cross_path,
        primary_before.path_acks_cross_path
    );
    assert_eq!(
        backup_after_receive.path_acks_same_path,
        backup_before.path_acks_same_path
    );

    // Closing the acknowledged path stops its MaxAckDelay timer. The pending PATH_ACK
    // must therefore become immediately sendable on the remaining open path.
    pair.close_path(Client, backup, 0u8.into())?;
    pair.drive_client();

    let primary_after_close = pair.path_stats(Client, PathId::ZERO).unwrap().frame_tx;
    let backup_after_close = pair.path_stats(Client, backup).unwrap().frame_tx;
    assert!(
        primary_after_close.path_acks_cross_path > primary_before.path_acks_cross_path,
        "an abandoned path's pending acknowledgment must fall back to an open path"
    );
    assert_eq!(
        backup_after_close.path_acks_same_path, backup_before.path_acks_same_path,
        "an abandoned path must not send its own pending acknowledgment"
    );

    pair.drive_server();
    assert!(
        pair.stats(Server).frame_rx.path_acks > server_before,
        "the peer must receive the fallback PATH_ACK"
    );
    Ok(())
}

#[test]
fn path_status() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let prev_status = pair.set_path_status(Client, PathId::ZERO, PathStatus::Backup)?;
    assert_eq!(prev_status, PathStatus::Available);

    // Send the frame to the server
    pair.drive();

    assert_eq!(
        pair.remote_path_status(Server, PathId::ZERO),
        Some(PathStatus::Backup)
    );

    let client_stats = pair.stats(Client);
    assert_eq!(client_stats.frame_tx.path_status_available, 0);
    assert_eq!(client_stats.frame_tx.path_status_backup, 1);
    assert_eq!(client_stats.frame_rx.path_status_available, 0);
    assert_eq!(client_stats.frame_rx.path_status_backup, 0);

    let server_stats = pair.stats(Server);
    assert_eq!(server_stats.frame_tx.path_status_available, 0);
    assert_eq!(server_stats.frame_tx.path_status_backup, 0);
    assert_eq!(server_stats.frame_rx.path_status_available, 0);
    assert_eq!(server_stats.frame_rx.path_status_backup, 1);
    Ok(())
}

#[test]
fn path_close_last_path() {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Closing the last path via the local API is not allowed.
    // Use Connection::close() to end the connection instead.
    assert_matches!(
        pair.close_path(Client, PathId::ZERO, 0u8.into()),
        Err(ClosePathError::LastOpenPath)
    );

    // Connection should still be alive
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));
}

#[test]
fn cid_issued_multipath() {
    let _guard = subscribe();
    const ACTIVE_CID_LIMIT: u64 = crate::cid_queue::CidQueue::LEN as _;
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let client_stats = pair.stats(Client);
    dbg!(&client_stats);

    // The client does not send NEW_CONNECTION_ID frames when multipath is enabled as they
    // are all sent after the handshake is completed.
    assert_eq!(client_stats.frame_tx.new_connection_id, 0);
    assert_eq!(
        client_stats.frame_tx.path_new_connection_id,
        MAX_PATHS as u64 * ACTIVE_CID_LIMIT
    );

    // The server sends NEW_CONNECTION_ID frames before the handshake is completed.
    // Multipath is only enabled *after* the handshake completes.  The first server-CID is
    // not issued but assigned by the client and changed by the server.
    assert_eq!(
        client_stats.frame_rx.new_connection_id,
        ACTIVE_CID_LIMIT - 1
    );
    assert_eq!(
        client_stats.frame_rx.path_new_connection_id,
        (MAX_PATHS - 1) as u64 * ACTIVE_CID_LIMIT
    );
}

#[test]
fn multipath_cid_rotation() {
    let _guard = subscribe();
    const CID_TIMEOUT: Duration = Duration::from_secs(2);

    let cid_generator_factory: fn() -> Box<dyn ConnectionIdGenerator> =
        || Box::new(*RandomConnectionIdGenerator::new(8).set_lifetime(CID_TIMEOUT));

    // Only test cid rotation on server side to have a clear output trace
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .with_server_endpoint_cfg(EndpointConfig {
            connection_id_generator_factory: Arc::new(cid_generator_factory),
            ..Default::default()
        })
        .connect();

    let mut round: u64 = 1;
    let mut stop = pair.time;
    let end = pair.time + 5 * CID_TIMEOUT;

    let mut active_cid_num = CidQueue::LEN as u64 + 1;
    active_cid_num = active_cid_num.min(LOCAL_CID_COUNT);
    let mut left_bound = 0;
    let mut right_bound = active_cid_num - 1;

    while pair.time < end {
        stop += CID_TIMEOUT;
        // Run a while until PushNewCID timer fires
        while pair.time < stop {
            if !pair.step()
                && let Some(time) = min_opt(pair.client.next_wakeup(), pair.server.next_wakeup())
            {
                pair.time = time;
            }
        }
        info!(
            "Checking active cid sequence range before {:?} seconds",
            round * CID_TIMEOUT.as_secs()
        );
        let _bound = (left_bound, right_bound);
        for path_id in 0..MAX_PATHS {
            assert_matches!(pair.conn(Server).active_local_path_cid_seq(path_id), _bound);
        }
        round += 1;
        left_bound += active_cid_num;
        right_bound += active_cid_num;
        pair.drive_server();
    }

    let stats = pair.stats(Server);

    // Server sends CIDs for PathId::ZERO before multipath is negotiated.
    assert_eq!(stats.frame_tx.new_connection_id, (CidQueue::LEN - 1) as u64);

    // For the first batch the PathId::ZERO CIDs have already been sent.
    let initial_batch: u64 = (MAX_PATHS - 1) as u64 * CidQueue::LEN as u64;
    // Each round expires all CIDs, so they all get re-issued.
    let each_round: u64 = MAX_PATHS as u64 * CidQueue::LEN as u64;
    // The final round only pushes one set of CIDs with expires_before, the round is not run
    // to completion to wait for the expiry messages from the client.
    let final_round: u64 = MAX_PATHS as u64;
    let path_new_cids = initial_batch + (round - 2) * each_round + final_round;
    debug_assert_eq!(path_new_cids, 73);
    assert_eq!(stats.frame_tx.path_new_connection_id, path_new_cids);

    // We don't retire any CIDs before multipath is negotiated.
    assert_eq!(stats.frame_tx.retire_connection_id, 0);

    // Server expires the CID of the initial sent by the client.
    assert_eq!(stats.frame_tx.path_retire_connection_id, 1);

    // Client only sends CIDs after multipath is negotiated.
    assert_eq!(stats.frame_rx.new_connection_id, 0);

    // Client does not expire CIDs, only the initial set for all the paths.
    assert_eq!(
        stats.frame_rx.path_new_connection_id,
        MAX_PATHS as u64 * CidQueue::LEN as u64
    );
    assert_eq!(stats.frame_rx.retire_connection_id, 0);

    // Test stops before last batch of retirements is sent.
    let path_retire_cids = MAX_PATHS as u64 * CidQueue::LEN as u64 * (round - 2);
    debug_assert_eq!(path_retire_cids, 60);
    assert_eq!(stats.frame_rx.path_retire_connection_id, path_retire_cids);
}

#[test]
fn issue_max_path_id() -> TestResult {
    let _guard = subscribe();

    // We enable multipath but initially do not allow any paths to be opened.
    // The client is allowed to create more paths immediately.
    let mut builder = ConnPair::builder().enable_multipath();
    builder
        .server_transport_cfg
        .max_concurrent_multipath_paths(1);
    let mut pair = builder.connect();

    pair.drive();
    info!("connected");

    // Server should only have sent NEW_CONNECTION_ID frames for now.
    let server_new_cids = CidQueue::LEN as u64 - 1;
    let mut server_path_new_cids = 0;
    let stats = pair.stats(Server);
    assert_eq!(stats.frame_tx.max_path_id, 0);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent PATH_NEW_CONNECTION_ID frames for PathId::ZERO.
    let client_new_cids = 0;
    let mut client_path_new_cids = CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);

    // Server increases MAX_PATH_ID.
    pair.set_max_concurrent_paths(Server, MAX_PATHS)?;
    pair.drive();
    let stats = pair.stats(Server);

    // Server should have sent MAX_PATH_ID and new CIDs
    server_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_tx.max_path_id, 1);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent CIDs for new paths
    client_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);

    Ok(())
}

/// A copy of [`issue_max_path_id`], but reordering the `MAX_PATH_ID` frame
/// that's sent from the server to the client, so that some `NEW_CONNECTION_ID`
/// frames arrive with higher path IDs than the most recently received
/// `MAX_PATH_ID` frame on the client side.
#[test]
fn issue_max_path_id_reordered() -> TestResult {
    let _guard = subscribe();

    // We enable multipath but initially do not allow any paths to be opened.
    // The client is allowed to create more paths immediately.
    let mut builder = ConnPair::builder().enable_multipath();
    builder
        .server_transport_cfg
        .max_concurrent_multipath_paths(1);
    let mut pair = builder.connect();

    pair.drive();
    info!("connected");

    // Server should only have sent NEW_CONNECTION_ID frames for now.
    let server_new_cids = CidQueue::LEN as u64 - 1;
    let mut server_path_new_cids = 0;
    let stats = pair.stats(Server);
    assert_eq!(stats.frame_tx.max_path_id, 0);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent PATH_NEW_CONNECTION_ID frames for PathId::ZERO.
    let client_new_cids = 0;
    let mut client_path_new_cids = CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);

    // Server increases MAX_PATH_ID, but we reorder the frame
    pair.set_max_concurrent_paths(Server, MAX_PATHS)?;
    pair.drive_server();
    // reorder the frames on the incoming side
    pair.reorder_inbound(Client);
    pair.drive();
    let stats = pair.stats(Server);

    // Server should have sent MAX_PATH_ID and new CIDs
    server_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_tx.max_path_id, 1);
    assert_eq!(stats.frame_tx.new_connection_id, server_new_cids);
    assert_eq!(stats.frame_tx.path_new_connection_id, server_path_new_cids);

    // Client should have sent CIDs for new paths
    client_path_new_cids += (MAX_PATHS as u64 - 1) * CidQueue::LEN as u64;
    assert_eq!(stats.frame_rx.new_connection_id, client_new_cids);
    assert_eq!(stats.frame_rx.path_new_connection_id, client_path_new_cids);

    Ok(())
}

#[test]
fn open_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(crate::PathEvent::Established { id  })) if id == path_id
    );

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(crate::PathEvent::Established { id  })) if id == path_id
    );
    Ok(())
}

#[test]
fn open_path_key_update() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;

    // Do a key-update at the same time as opening the new path.
    pair.force_key_update(Client);

    pair.drive();
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(crate::PathEvent::Established { id  })) if id == path_id
    );

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(crate::PathEvent::Established { id  })) if id == path_id
    );
    Ok(())
}

/// Client starts opening a path but the server fails to validate the path
///
/// The client should receive an event closing the path.
#[test]
fn open_path_validation_fails_server_side() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let different_addr = FourTuple {
        remote: SocketAddr::new([9, 8, 7, 6].into(), 5),
        local_ip: None,
    };
    assert_ne!(different_addr.remote, Pair::SERVER_ADDR);
    assert_ne!(different_addr.remote, Pair::CLIENT_ADDR);
    let path_id = pair.open_path(Client, different_addr, PathStatus::Available)?;

    // block the server from receiving anything
    while pair.blackhole_step(true, false) {}
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(crate::PathEvent::Abandoned { id, reason: PathAbandonReason::ValidationFailed  })) if id == path_id
    );

    assert!(pair.poll(Server).is_none());
    Ok(())
}

/// Client starts opening a path but the client fails to validate the path
///
/// The server should receive an event close the path
#[test]
fn open_path_validation_fails_client_side() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // make sure the new path cannot be validated using the existing path
    let new_addr = SocketAddr::new([9, 8, 7, 6].into(), 5);
    assert_ne!(new_addr, Pair::SERVER_ADDR);
    assert_ne!(new_addr, Pair::CLIENT_ADDR);
    pair.routes.as_basic_mut().client_addr = new_addr;

    let network_path = FourTuple {
        remote: pair.routes.public_server_addr(),
        local_ip: None,
    };
    let path_id = pair.open_path(Client, network_path, PathStatus::Available)?;

    // Make sure the client's path open makes it through to the server and is processed.
    pair.drive_client();
    pair.drive_server();

    info!("dropping client inbound queue");
    pair.client.inbound.clear();

    // Sever the connection and run it to idle.
    // This makes sure that
    // - path validation can't succeed because path responses don't make it through and
    // - the server needs to decide to close the path on its own, because path abandons
    //   don't make it through.
    while pair.blackhole_step(true, true) {}

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Abandoned { id, reason: PathAbandonReason::ValidationFailed  }))
            if id == path_id
    );
    Ok(())
}

/// Client opens a path, then abandons, then calls open_path_ensure.
///
/// In the end there should be an open path.
#[test]
fn open_path_ensure_after_abandon() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let mut second_client_addr = pair.routes.as_basic().client_addr;
    let mut second_server_addr = pair.routes.as_basic().server_addr;
    second_client_addr.set_port(second_client_addr.port() + 1);
    second_server_addr.set_port(second_server_addr.port() + 1);
    pair.routes = ManyToManyRouting::simple_symmetric(
        [pair.routes.as_basic().client_addr, second_client_addr],
        [pair.routes.as_basic().server_addr, second_server_addr],
    )
    .into();

    let second_path = FourTuple {
        local_ip: Some(second_client_addr.ip()),
        remote: second_server_addr,
    };

    info!("opening path 1");
    let path_id = pair.open_path(Client, second_path, PathStatus::Available)?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id  })) if id == path_id
    );

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id  })) if id == path_id
    );

    info!("closing path {path_id}");
    pair.close_path(Client, path_id, 0u8.into())?;
    pair.drive();

    // The path should be closed:
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::ApplicationClosed { error_code }
        }))
            if id == path_id && error_code == 0u8.into()
    );

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::RemoteAbandoned { error_code }
        }))
            if id == path_id && error_code == 0u8.into()
    );

    pair.drive();

    // The path should be discarded:
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Discarded { id, .. })) if id == path_id
    );

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Discarded { id, .. })) if id == path_id
    );

    info!("opening path 2");
    let (path_id, existed) = pair.open_path_ensure(Client, second_path, PathStatus::Available)?;
    pair.drive();

    assert!(!existed);

    // The path should have been opened:
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id  })) if id == path_id
    );

    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id  })) if id == path_id
    );
    Ok(())
}

#[test]
fn close_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();
    assert_ne!(path_id, PathId::ZERO);

    let stats0 = pair.stats(Client);
    assert_eq!(stats0.frame_tx.path_abandon, 0);
    assert_eq!(stats0.frame_rx.path_abandon, 0);
    assert_eq!(stats0.frame_tx.max_path_id, 0);
    assert_eq!(stats0.frame_rx.max_path_id, 0);

    info!("closing path 0");
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive();

    let stats1 = pair.stats(Client);
    assert_eq!(stats1.frame_tx.path_abandon, 1);
    assert_eq!(stats1.frame_rx.path_abandon, 1);
    assert_eq!(stats1.frame_tx.max_path_id, 1);
    assert_eq!(stats1.frame_rx.max_path_id, 1);
    assert!(stats1.frame_tx.path_new_connection_id > stats0.frame_tx.path_new_connection_id);
    assert!(stats1.frame_rx.path_new_connection_id > stats0.frame_rx.path_new_connection_id);
    Ok(())
}

/// Regression: We never emit [`PathEvent::Established`] after [`PathEvent::Abandoned`].
///
/// It may happen that a PATH_RESPONSE validating a path is received after a
/// PATH_ABANDON (due to reordering or the different path latencies). We used to
/// emit a [`PathEvent::Establish`] *after* [`PathEvent::Abandoned`], which makes
/// no sense. This was fixed, and this test ensures that this doesn't happen again.
#[test]
fn no_establish_after_abandon() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    assert_ne!(path_id, PathId::ZERO);

    // Client sends PATH_CHALLENGE
    pair.drive_client();
    pair.advance_time();
    // Server receives PATH_CHALLENGE and replies with PATH_RESPONSE and its
    // own PATH_CHALLENGE. Server has *not* validated the path yet.
    pair.drive_server();
    pair.advance_time();
    // Client receives PATH_RESPONSE and PATH_CHALLENGE. It has now validated
    // the path, and sends a PATH_RESPONSE. We hold back the packet containing
    // the PATH_RESPONSE.
    pair.drive_client();
    let withheld: Vec<_> = pair.server.inbound.drain(..).collect();
    assert!(
        !withheld.is_empty(),
        "expected the client's PATH_RESPONSE to be in flight"
    );

    // Now abandon the path on the client and deliver the PATH_ABANDON frame to
    // the server.
    pair.close_path(Client, path_id, 0u8.into())?;
    pair.advance_time();
    pair.drive_client();
    pair.drive_server();

    // Now deliver the withheld PATH_RESPONSE. It validates the *already
    // abandoned* path.
    for pkt in withheld {
        pair.server.inbound.push_back(pkt);
    }
    pair.advance_time();
    pair.drive_client();
    pair.drive_server();

    // On the client, we get Established and then Abandoned
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id }))
        if id == path_id
    );
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::ApplicationClosed { .. }
        }))
        if id == path_id
    );
    assert_matches!(pair.poll(Client), None);

    // Server only gets a PathEvent::Abandoned. This is the actual regression test:
    // Before the fix, we would get a PathEvent::Established after Abandoned.
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::RemoteAbandoned { .. }
        }))
        if id == path_id
    );
    assert_matches!(pair.poll(Server), None);

    Ok(())
}

#[test]
fn close_last_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();
    assert_ne!(path_id, PathId::ZERO);

    info!("client closes path 0");
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;

    info!("server closes path 1");
    pair.close_path(Server, PathId(1), 0u8.into())?;

    pair.drive();

    assert!(pair.is_closed(Server));
    assert!(pair.is_closed(Client));
    Ok(())
}

#[test]
fn per_path_observed_address() -> TestResult {
    let _guard = subscribe();
    // create the endpoint pair with both address discovery and multipath enabled
    let transport_cfg = TransportConfig {
        max_concurrent_multipath_paths: NonZeroU32::new(MAX_PATHS),
        address_discovery_role: crate::address_discovery::Role::both(),
        ..TransportConfig::default()
    };
    let (mut pair, client_events, _server_events) = ConnPair::builder()
        .with_transport_cfg(transport_cfg)
        .lax_connect();

    info!("connected");
    pair.drive();

    let first_addr = pair.routes.as_basic().client_addr;
    let first_server_addr = pair.routes.as_basic().server_addr;
    let mut second_client_addr = first_addr;
    let mut second_server_addr = first_server_addr;
    second_client_addr.set_port(second_client_addr.port() + 1);
    second_server_addr.set_port(second_server_addr.port() + 1);
    pair.routes = ManyToManyRouting::simple_symmetric(
        [first_addr, second_client_addr],
        [first_server_addr, second_server_addr],
    )
    .into();

    let second_path = FourTuple {
        local_ip: Some(second_client_addr.ip()),
        remote: second_server_addr,
    };
    let path_id = pair.open_path(Client, second_path, PathStatus::Available)?;
    pair.drive();

    let mut found_first = false;
    let mut found_second = false;
    let post_connect_events = std::iter::from_fn(|| pair.poll(Client));
    for event in client_events.into_iter().chain(post_connect_events) {
        if let Event::Path(PathEvent::ObservedAddr { id, addr }) = event {
            if id == PathId::ZERO && addr == first_addr {
                found_first = true;
            } else if id == path_id && addr == second_client_addr {
                found_second = true;
            }
        }
    }
    assert!(found_first);
    assert!(found_second);

    Ok(())
}

#[test]
fn mtud_on_two_paths() -> TestResult {
    let _guard = subscribe();

    let mut builder = ConnPair::builder()
        .with_mtu(1200) // Start with a small MTU
        .enable_multipath();
    builder.server_transport_cfg.max_idle_timeout = None;
    builder.client_transport_cfg.max_idle_timeout = None;
    let mut pair = builder.connect();

    assert_eq!(pair.conn(Client).path_mtu(PathId::ZERO), 1200);

    // Open a 2nd path.
    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    // Ensure the path opened correctly.
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(crate::PathEvent::Established { id  })) if id == path_id
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(crate::PathEvent::Established { id  })) if id == path_id
    );

    // MTU should be 1200 for both paths.
    assert_eq!(pair.conn(Client).path_mtu(PathId::ZERO), 1200);
    assert_eq!(pair.conn(Client).path_mtu(path_id), 1200);

    // The default MtuDiscoveryConfig::upper_bound is 1452, the default
    // MtuDiscoveryConfig::interval is 600s.
    pair.mtu = 1452;
    pair.time += Duration::from_secs(600);
    info!("Bumping MTU to: {}", pair.mtu);
    pair.drive();

    info!("MTU Path 0: {}", pair.conn(Client).path_mtu(PathId::ZERO));
    info!(
        "MTU Path {}: {}",
        path_id,
        pair.conn(Client).path_mtu(path_id)
    );

    // Both paths should have found the new MTU.
    assert_eq!(pair.conn(Client).path_mtu(PathId::ZERO), 1452);
    assert_eq!(pair.conn(Client).path_mtu(path_id), 1452);
    Ok(())
}

/// Closing a path locally may be rejected if this leaves the endpoint without validated paths. For
/// paths closed by the remote, however, a `PATH_ABANDON` frame must be accepted. In
/// particular, it should not kill the connection.
///
/// This is a regression test.
#[test]
fn remote_can_close_last_validated_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    pair.routes.as_basic_mut().passive_migration(Client);
    let route = FourTuple {
        remote: pair.routes.public_server_addr(),
        local_ip: None,
    };
    pair.open_path(Client, route, PathStatus::Available)?;
    pair.drive_client();
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive();

    // Neither side of the connection should error on close
    let mut close = None;
    for side in [Client, Server] {
        while let Some(event) = pair.poll(side) {
            if let Event::ConnectionLost { reason } = event {
                close = Some(reason);
            }
        }
        assert_eq!(close, None);
    }

    Ok(())
}

/// With multipath and hint=None, the client defaults to non-recoverable: the old path is closed
/// with PATH_UNSTABLE_OR_POOR and a new path is opened. Data still flows on the new path.
#[test]
fn network_change_multipath_no_hint_replaces_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Simulate a passive migration + network change with no hint
    pair.routes.as_basic_mut().passive_migration(Client);
    pair.handle_network_change(Client, None);

    pair.drive();

    // A new path should be opened and the old one should be closed
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned {
            id: PathId(0),
            reason: PathAbandonReason::UnusableAfterNetworkChange
        }))
    );
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id: PathId(1) }))
    );

    // The server sees the old path closed with PATH_UNSTABLE_OR_POOR
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Abandoned {
            id: PathId::ZERO,
            reason: PathAbandonReason::RemoteAbandoned { error_code }
        }))
        if error_code == TransportErrorCode::PATH_UNSTABLE_OR_POOR.into()
    );
    // And then sees the new path
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id: PathId(1) }))
    );
    // Both client and server see the old path as discarded
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Discarded {
            id: PathId::ZERO,
            ..
        }))
    );
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Discarded {
            id: PathId::ZERO,
            ..
        }))
    );

    // Data should flow on the new path
    let s = pair.streams(Client).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"after network change";
    pair.send_stream(Client, s).write(MSG).unwrap();
    pair.send_stream(Client, s).finish().unwrap();
    pair.drive();

    assert_matches!(
        pair.poll(Server),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(stream) if stream == s);
    let mut recv = pair.recv_stream(Server, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.bytes == MSG
    );
    let _ = chunks.finalize();

    Ok(())
}

/// With two paths open and a selective hint, only the non-recoverable path gets replaced.
/// The recoverable path is kept and pinged for liveness.
#[test]
fn network_change_selective_hint() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Open a second path
    let server_addr = pair.routes.public_server_addr();
    let second_path = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id })) if id == second_path
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id })) if id == second_path
    );

    // A hint that says PathId::ZERO is recoverable but the second path is not
    #[derive(Debug)]
    struct SelectiveHint(PathId);
    impl NetworkChangeHint for SelectiveHint {
        fn is_path_recoverable(&self, path_id: PathId, _network_path: FourTuple) -> bool {
            path_id == self.0
        }
    }
    let hint = SelectiveHint(PathId::ZERO);

    pair.routes.as_basic_mut().passive_migration(Client);
    pair.handle_network_change(Client, Some(&hint));

    pair.drive();

    // The second path (non-recoverable) should be replaced: a new path opens
    // PathId::ZERO (recoverable) should stay open (no Closed event for it)
    let mut client_events = Vec::new();
    while let Some(event) = pair.poll(Client) {
        client_events.push(event);
    }

    // There should be an Opened event for the replacement path
    assert!(
        client_events
            .iter()
            .any(|e| matches!(e, Event::Path(PathEvent::Established { .. }))),
        "expected an Opened event for the replacement path, got: {client_events:?}"
    );
    // PathId::ZERO should NOT have been closed
    assert!(
        !client_events.iter().any(|e| matches!(
            e,
            Event::Path(PathEvent::Discarded {
                id: PathId::ZERO,
                ..
            })
        )),
        "PathId::ZERO should not have been closed: {client_events:?}"
    );

    Ok(())
}

/// Server-side network change with two paths and a selective hint.
///
/// The non-recoverable path is abandoned, leaving only the recoverable one.
#[test]
fn network_change_server_two_paths_selective_hint() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Open a second path from the client side.
    let server_addr = pair.routes.public_server_addr();
    let second_path = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id })) if id == second_path
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id })) if id == second_path
    );

    // Hint: The provided PathId is recoverable, others are not.
    #[derive(Debug)]
    struct SelectiveHint(PathId);
    impl NetworkChangeHint for SelectiveHint {
        fn is_path_recoverable(&self, path_id: PathId, _network_path: FourTuple) -> bool {
            path_id == self.0
        }
    }

    // Signal network change without actually changing the server's local address. This
    // means the client will not see an actual network change and keep accepting the packets
    // from the server. If the server's address would change it would discard the server's
    // packets since the server may not migrate.
    pair.handle_network_change(Server, Some(&SelectiveHint(second_path)));

    pair.drive();

    // The non-recoverable path is abandoned on the server. No replacement opens because
    // servers cannot call open_path.
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Abandoned {
            id,
            reason: PathAbandonReason::UnusableAfterNetworkChange,
        })) if id == PathId::ZERO
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Discarded { id, .. })) if id == PathId::ZERO
    );
    assert_matches!(pair.poll(Server), None);

    // The client sees PathId::ZERO abandoned by the remote, then discards it.
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned {
            id: PathId::ZERO,
            reason: PathAbandonReason::RemoteAbandoned { .. },
        }))
    );
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Discarded {
            id: PathId::ZERO,
            ..
        }))
    );
    assert_matches!(pair.poll(Client), None);

    Ok(())
}

/// Server-side network change with a single path and a non-recoverable hint.
///
/// The path cannot be closed because it is the last one.
#[test]
fn network_change_server_single_path_non_recoverable_falls_back() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Hint that says all paths are non-recoverable
    #[derive(Debug)]
    struct NonRecoverableHint;
    impl NetworkChangeHint for NonRecoverableHint {
        fn is_path_recoverable(&self, _path_id: PathId, _network_path: FourTuple) -> bool {
            false
        }
    }

    // Signal network change without actually changing the server's local address. This
    // means the client will not see an actual network change and keep accepting the packets
    // from the server. If the server's address would change it would discard the server's
    // packets since the server may not migrate.
    pair.handle_network_change(Server, Some(&NonRecoverableHint));
    pair.drive();

    // The path should NOT be abandoned. The last open path cannot be closed.
    assert_matches!(pair.poll(Server), None);
    assert_matches!(pair.poll(Client), None);

    Ok(())
}

/// Server-side network change with no hint defaults to recoverable. Both paths stay open.
#[test]
fn network_change_server_no_hint_recovers() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Open a second path from the client side.
    let server_addr = pair.routes.public_server_addr();
    let second_path = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id })) if id == second_path
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id })) if id == second_path
    );

    // Signal network change without actually changing the server's local address. This
    // means the client will not see an actual network change and keep accepting the packets
    // from the server. If the server's address would change it would discard the server's
    // packets since the server may not migrate.
    pair.handle_network_change(Server, None);
    pair.drive();

    // No path events: the server defaults to recoverable when no hint is provided.
    // Neither path should be abandoned.
    assert_matches!(pair.poll(Server), None);
    assert_matches!(pair.poll(Client), None);

    Ok(())
}

/// Checks that the deadline given before a path fails to be considered open start only when the
/// first packet is sent.
///
/// This is a regression test. See <https://github.com/n0-computer/noq/issues/435>
#[test]
fn path_open_deadline_is_set_on_send() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;

    // Fast-forward time well past 3×PTO without letting any transmit happen on the new
    // path.
    let far_future = pair.time + Duration::from_secs(5);
    pair.handle_timeout(Client, far_future);

    assert!(
        pair.poll(Client).is_none(),
        "path was abandoned before any challenge was sent (issue #456)"
    );

    // Now let the challenge be sent and the path to be opened.
    pair.time = far_future;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id })) if id == path_id,
        "path should open successfully after the challenge is sent"
    );

    Ok(())
}

#[test]
fn path_scheduling_path_status() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    info!("Setting Path 0 to PathStatus::Backup");
    let prev_status = pair.set_path_status(Client, PathId::ZERO, PathStatus::Backup)?;
    assert_eq!(prev_status, PathStatus::Available);

    // Send the frame to the server
    pair.drive();

    assert_eq!(
        pair.remote_path_status(Server, PathId::ZERO),
        Some(PathStatus::Backup)
    );

    info!("Opening Path 1 with PathStatus::Available");
    let server_addr = pair.routes.public_server_addr();
    let path_1 = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    let stats_path0_t0 = pair.conn_mut(Client).path_stats(PathId::ZERO).unwrap();
    let stats_path1_t0 = pair.conn_mut(Client).path_stats(path_1).unwrap();

    info!("Sending STREAM frame");
    let s = pair.streams(Client).open(Dir::Uni).unwrap();
    pair.send_stream(Client, s).write(b"hello").unwrap();
    pair.drive();

    let stats_path0_t1 = pair.conn_mut(Client).path_stats(PathId::ZERO).unwrap();
    let stats_path1_t1 = pair.conn_mut(Client).path_stats(path_1).unwrap();

    info!("assert");
    assert!((stats_path0_t1.udp_tx.datagrams - stats_path0_t0.udp_tx.datagrams) == 0);
    assert!((stats_path1_t1.udp_tx.datagrams - stats_path1_t0.udp_tx.datagrams) > 0);

    Ok(())
}

#[test]
fn server_abandon_last_verified_path() -> TestResult {
    // The client abandons the last verified path the server has. The server is expected to
    // send PATH_ABANDON on the abandoned path itself in this case.

    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Passively migrate the client and immediately open a second path. This way the client
    // will assume the 2nd path is validated but to the server it will be
    // un-validated. Otherwise the client would not allow closing path 0 since there would
    // be no validated path left over.
    pair.routes.as_basic_mut().passive_migration(Client);
    let route = FourTuple {
        remote: pair.routes.public_server_addr(),
        local_ip: None,
    };
    pair.open_path(Client, route, PathStatus::Available)?;
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive();

    // We need to move past the Abandoned and Open events, we really only care about getting
    // the stats from the abandoned path.
    let evt = pair.poll(Server);
    assert!(matches!(
        evt,
        Some(Event::Path(PathEvent::Abandoned { .. }))
    ));
    let evt = pair.poll(Server);
    assert!(matches!(
        evt,
        Some(Event::Path(PathEvent::Established { .. }))
    ));

    let evt = pair.poll(Server);
    let Some(Event::Path(PathEvent::Discarded { path_stats, .. })) = evt else {
        panic!("did not get path discarded event");
    };

    assert_eq!(path_stats.frame_tx.path_abandon, 1);

    Ok(())
}

/// Remote abandons a non-last path: error code is propagated in the event.
#[test]
fn remote_path_abandon_with_remaining_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let _path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    pair.close_path(Server, PathId::ZERO, 42u8.into())?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned {
            id: PathId::ZERO,
            reason: PathAbandonReason::RemoteAbandoned { error_code }
        })) if error_code == 42u8.into()
    );
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));

    Ok(())
}

/// Remote abandons the last path, no new path opened: connection closes after grace period.
#[test]
fn remote_path_abandon_last_path_closes_connection() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Open a second path so we can close path 0 normally
    let server_addr = pair.routes.public_server_addr();
    let _path1 = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    // Close path 0 normally (path 1 remains)
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    // Simulate remote abandoning path 1 (now the client's last path)
    // We use force_remote_abandon because in a real scenario the PATH_ABANDON
    // arrives via a packet on the same path, which auto-creates the path on
    // the receiver if it doesn't exist, making packet-dropping approaches
    // unable to create a true last-path scenario in tests.
    pair.force_remote_abandon(Client, PathId::from(1u8));
    pair.drive();

    // After the grace period (no new path opened), the client should be closed.
    assert!(
        pair.is_closed(Client),
        "client should be closed after grace period expired"
    );

    // Verify the client saw the abandon and connection close events.
    let mut saw_abandon = false;
    let mut saw_close = false;
    while let Some(event) = pair.poll(Client) {
        match event {
            Event::Path(PathEvent::Abandoned {
                reason: PathAbandonReason::RemoteAbandoned { .. },
                ..
            }) => saw_abandon = true,
            Event::ConnectionLost { .. } => saw_close = true,
            _ => {}
        }
    }
    assert!(
        saw_abandon,
        "client should see path abandon event for last path"
    );
    assert!(saw_close, "client should see connection lost event");

    Ok(())
}

/// Remote abandons the last path, client opens a new path within grace period: connection survives.
#[test]
fn remote_path_abandon_last_path_client_opens_new() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Open path 1, close path 0 normally
    let server_addr = pair.routes.public_server_addr();
    let _path1 = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive();
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    // Simulate remote abandoning path 1 (client's last path)
    pair.force_remote_abandon(Client, PathId::from(1u8));

    // Client opens a new path within the grace period
    let new_path = pair.routes.public_server_addr();
    let new_path_id = pair.open_path(
        Client,
        FourTuple::from_remote(new_path),
        PathStatus::Available,
    )?;
    pair.drive();

    assert!(!pair.is_closed(Client), "client should survive");
    assert!(!pair.is_closed(Server), "server should survive");

    let mut saw_abandon = false;
    let mut saw_opened = false;
    while let Some(event) = pair.poll(Client) {
        match event {
            Event::Path(PathEvent::Abandoned {
                reason: PathAbandonReason::RemoteAbandoned { .. },
                ..
            }) => saw_abandon = true,
            Event::Path(PathEvent::Established { id }) if id == new_path_id => saw_opened = true,
            _ => {}
        }
    }
    assert!(saw_abandon, "client should see abandon for last path");
    assert!(saw_opened, "client should see new path opened");

    Ok(())
}

#[test]
fn abandon_path_data_continues() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Open a second path
    let server_addr = pair.routes.public_server_addr();
    let path1 = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    // Drain open events
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    // Client abandons path 0 (picoquic: `picoquic_abandon_path(cnx_client, 0, 0, "test", time)`)
    info!("client abandons path 0");
    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive();

    // Drain abandon + discard events
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    // Picoquic verification: both sides should have exactly 1 path remaining.
    // In noq, we check that path 0 is abandoned and path 1 is still alive.
    assert!(
        pair.path_status(Client, path1).is_ok(),
        "client should still have path 1"
    );
    assert!(
        pair.path_status(Server, path1).is_ok(),
        "server should still have path 1"
    );

    // Data should still flow on the remaining path (picoquic sends test_scenario_multipath)
    let s = pair.streams(Client).open(Dir::Uni).unwrap();
    const MSG: &[u8] = b"data after path abandon";
    pair.send_stream(Client, s).write(MSG).unwrap();
    pair.send_stream(Client, s).finish().unwrap();
    pair.drive();

    assert_matches!(
        pair.poll(Server),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(stream) if stream == s);
    let mut recv = pair.recv_stream(Server, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(
        chunks.next(usize::MAX),
        Ok(Some(chunk)) if chunk.bytes == MSG
    );
    let _ = chunks.finalize();

    // Connection alive
    assert!(!pair.is_closed(Client));
    assert!(!pair.is_closed(Server));

    Ok(())
}

/// Regression test: a NewIdentifiers reply arriving after a path is abandoned
/// must not result in the frames being queued for transmission in
/// `pending.new_cids`.
#[test]
fn new_identifiers_after_abandon_does_not_panic() -> TestResult {
    use crate::shared::{ConnectionEvent, ConnectionEventInner, IssuedCid};
    use crate::token::ResetToken;

    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    // A second path is needed so close_path(0) is not the last open path.
    let server_addr = pair.routes.public_server_addr();
    let _path1 = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    let cid_seq_before = pair.conn(Client).active_local_path_cid_seq(0);

    pair.close_path(Client, PathId::ZERO, 0u8.into())?;
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    // Inject a NewIdentifiers reply for the just-abandoned path.
    let synthetic_seq = cid_seq_before.1 + 1;
    let issued = vec![IssuedCid {
        path_id: PathId::ZERO,
        sequence: synthetic_seq,
        id: ConnectionId::new(&[0xAAu8; 8]),
        reset_token: ResetToken::from([0u8; crate::RESET_TOKEN_SIZE]),
    }];
    let late_event = ConnectionEvent(ConnectionEventInner::NewIdentifiers(
        issued, pair.time, 8, None,
    ));
    pair.handle_event(Client, late_event);

    // The CID must not have been added to local_cid_state, otherwise it would be
    // queued in `pending.new_cids` and later sent as a NEW_CONNECTION_ID frame
    // for an abandoned path.
    let cid_seq_after = pair.conn(Client).active_local_path_cid_seq(0);
    assert_eq!(cid_seq_before, cid_seq_after);

    Ok(())
}

/// Ported from picoquic `multipath_test_ab1`. Abandon + reopen cycle, 3 rounds.
#[test]
fn abandon_cycle() -> TestResult {
    let _guard = subscribe();

    let mut pair = ConnPair::builder().enable_multipath().connect();

    // Set up addresses for multiple paths
    let routing = pair.routes.as_basic();
    let mut addrs_client = vec![routing.client_addr];
    let mut addrs_server = vec![routing.server_addr];
    for i in 1..6u16 {
        let mut ca = routing.client_addr;
        ca.set_port(ca.port() + i);
        addrs_client.push(ca);
        let mut sa = routing.server_addr;
        sa.set_port(sa.port() + i);
        addrs_server.push(sa);
    }
    pair.routes =
        ManyToManyRouting::simple_symmetric(addrs_client.clone(), addrs_server.clone()).into();

    // Cycle: open a second path, abandon path 0, verify cleanup, repeat with new paths.
    // Each cycle uses a fresh pair of addresses.
    let mut current_path = PathId::ZERO;
    for cycle in 0..3u16 {
        let addr_idx = (cycle as usize) + 1;
        let new_path_net = FourTuple {
            local_ip: Some(addrs_client[addr_idx].ip()),
            remote: addrs_server[addr_idx],
        };

        info!("cycle {cycle}: opening new path on addr index {addr_idx}");
        let new_path = pair.open_path(Client, new_path_net, PathStatus::Available)?;
        pair.drive();

        // Drain events
        while pair.poll(Client).is_some() {}
        while pair.poll(Server).is_some() {}

        info!("cycle {cycle}: abandoning path {current_path}");
        pair.close_path(Client, current_path, 0u8.into())?;
        pair.drive();

        // Drain events (abandon + discard)
        while pair.poll(Client).is_some() {}
        while pair.poll(Server).is_some() {}

        // Verify the abandoned path is gone and the new path remains
        assert!(
            pair.path_status(Client, current_path).is_err(),
            "cycle {cycle}: abandoned path should be gone"
        );
        assert!(
            pair.path_status(Client, new_path).is_ok(),
            "cycle {cycle}: new path should be alive"
        );

        // Verify connection is alive
        assert!(
            !pair.is_closed(Client),
            "cycle {cycle}: client should be alive"
        );
        assert!(
            !pair.is_closed(Server),
            "cycle {cycle}: server should be alive"
        );

        // Picoquic verifies CID stash has >= 2 entries; we verify data still works.
        let s = pair.streams(Client).open(Dir::Uni).unwrap();
        let msg = format!("cycle {cycle}");
        pair.send_stream(Client, s).write(msg.as_bytes()).unwrap();
        pair.send_stream(Client, s).finish().unwrap();
        pair.drive();

        // Server should receive the data
        assert_matches!(
            pair.poll(Server),
            Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
        );
        assert_matches!(pair.streams(Server).accept(Dir::Uni), Some(stream) if stream == s);
        let mut recv = pair.recv_stream(Server, s);
        let mut chunks = recv.read(false).unwrap();
        assert_matches!(
            chunks.next(usize::MAX),
            Ok(Some(chunk)) if chunk.bytes == msg.as_bytes()
        );
        let _ = chunks.finalize();

        current_path = new_path;
    }

    Ok(())
}

/// NAT traversal round revalidates an existing path via new PATH_CHALLENGE.
#[test]
fn nat_traversal_revalidates_existing_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .enable_nat_traversal()
        .connect();

    let server_addr = pair.routes.as_basic().server_addr;
    let client_addr = pair.routes.as_basic().client_addr;

    pair.add_nat_traversal_address(Server, server_addr)?;
    pair.add_nat_traversal_address(Client, client_addr)?;
    pair.drive();

    let probed = pair.initiate_nat_traversal_round(Client)?;
    assert_eq!(probed.len(), 1);
    assert_eq!(probed[0], server_addr);
    pair.drive();

    assert_eq!(
        pair.path_status(Client, PathId::ZERO)?,
        PathStatus::Available
    );

    let challenges_before = pair.stats(Client).frame_tx.path_challenge;

    // Second round with the same addresses should trigger revalidation
    let probed = pair.initiate_nat_traversal_round(Client)?;
    assert_eq!(probed.len(), 1);
    pair.drive_bounded(20);

    let challenges_after = pair.stats(Client).frame_tx.path_challenge;
    assert!(
        challenges_after > challenges_before,
        "expected new PATH_CHALLENGE for existing path \
         (before={challenges_before}, after={challenges_after})"
    );

    Ok(())
}

/// After a silent gap, PTO backs off exponentially and can reach minutes.
/// The 2s PTO cap ensures recovery happens promptly once connectivity returns.
#[test]
fn path_recovers_after_silent_gap_via_keepalive() -> TestResult {
    let _guard = subscribe();

    let mut builder = ConnPair::builder().enable_multipath();
    builder
        .server_transport_cfg
        .default_path_max_idle_timeout(Some(Duration::from_secs(60)));
    builder
        .client_transport_cfg
        .default_path_max_idle_timeout(Some(Duration::from_secs(60)));
    let mut pair = builder.connect();

    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    let s = pair.streams(Server).open(Dir::Uni).unwrap();
    pair.send_stream(Server, s).write(&[42u8; 5000]).unwrap();
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    );
    assert_matches!(pair.streams(Client).accept(Dir::Uni), Some(stream) if stream == s);
    let mut recv = pair.recv_stream(Client, s);
    let mut chunks = recv.read(false).unwrap();
    let mut total_read = 0;
    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
        total_read += chunk.bytes.len();
    }
    let _ = chunks.finalize();
    info!("read {total_read} bytes before gap");
    assert!(total_read > 0, "should have received initial data");

    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    pair.send_stream(Server, s).write(&[43u8; 5000]).unwrap();

    info!("starting silent gap");
    let gap_start = pair.time;
    for _ in 0..10 {
        if !pair.blackhole_step(true, true) {
            break;
        }
    }
    let gap_duration = pair.time - gap_start;
    info!("gap lasted {:?}", gap_duration);

    pair.send_stream(Server, s).write(b"after gap").unwrap();
    pair.send_stream(Server, s).finish().unwrap();

    info!("gap ended, driving to recovery");
    let mut received_post_gap = false;
    for i in 0..50 {
        if pair.is_closed(Client) || pair.is_closed(Server) {
            info!("connection died at step {i}");
            break;
        }
        pair.step();

        while let Some(event) = pair.poll(Client) {
            if matches!(&event, Event::Stream(StreamEvent::Readable { .. })) {
                info!("client received data at step {i}");
                received_post_gap = true;
            }
        }
        if received_post_gap {
            break;
        }
    }

    assert!(!pair.is_closed(Client), "client should survive the gap");
    assert!(!pair.is_closed(Server), "server should survive the gap");
    assert!(
        received_post_gap,
        "client should receive data after the gap recovers"
    );

    Ok(())
}

/// Tests NAT traversal manages to open a 2nd path.
#[test]
fn test_simple_nat_traveral_opens_path() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .enable_nat_traversal()
        .with_routes(SimpleFirewallRouting::new().into())
        .connect();

    info!("adding addrs");
    pair.add_nat_traversal_address(Server, SimpleFirewallRouting::SERVER_FW_ADDR)?;
    pair.add_nat_traversal_address(Client, SimpleFirewallRouting::CLIENT_FW_ADDR)?;
    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(
        event,
        Event::NatTraversal(n0_nat_traversal::Event::AddressAdded(_))
    );

    info!("init NAT traversal");
    pair.initiate_nat_traversal_round(Client)?;

    // Ensure we have no more events queued
    assert_matches!(pair.poll(Client), None);
    assert_matches!(pair.poll(Server), None);

    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    let event = pair.poll(Server).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    Ok(())
}

/// Test that a PATH_CHALLENGE is added to a PATH_RESPONSE for NAT traversal.
#[test]
fn test_simple_nat_traversal_challenge_with_response() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .enable_nat_traversal()
        .connect();

    info!("setting routes, adding addrs");
    pair.routes = SimpleFirewallRouting::new().into();
    pair.add_nat_traversal_address(Server, SimpleFirewallRouting::SERVER_FW_ADDR)?;
    pair.add_nat_traversal_address(Client, SimpleFirewallRouting::CLIENT_FW_ADDR)?;
    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(
        event,
        Event::NatTraversal(n0_nat_traversal::Event::AddressAdded(_))
    );

    info!("init NAT traversal");
    pair.initiate_nat_traversal_round(Client)?;

    // Ensure we have no more events queued
    assert_matches!(pair.poll(Client), None);
    assert_matches!(pair.poll(Server), None);

    // Client sends probe (blocked) + REACH_OUT, server send probe. Both firewalls open.
    pair.step();

    // Client receives probe, includes its own challenge with the response.
    let stats0 = pair.stats(Client);
    pair.step();
    let stats1 = pair.stats(Client);

    // Without the challenge-with-response only a PATH_RESPONSE would have been sent.
    assert_eq!(
        stats1.frame_tx.path_response - stats0.frame_tx.path_response,
        1
    );
    assert_eq!(
        stats1.frame_tx.path_challenge - stats0.frame_tx.path_challenge,
        1
    );

    // Continue till the end.
    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    let event = pair.poll(Server).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    Ok(())
}

/// Tests a "very easy NAT" for the server with a "hard NAT" for the client.
///
/// Here "very easy NAT" is an EIM+EIF NAT. The port is opened by the QAD probe. "hard NAT"
/// is an EDM NAT.
#[test]
fn test_hard_nat_client_opens_path() -> TestResult {
    let _guard = subscribe();
    let mut routing = SimpleFirewallRouting::new();
    // By configuring the server side to be open it emulates an EIM+EIF NAT: the QAD probe
    // already opened the firewall.
    routing.server_firewall_open = true;
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .enable_nat_traversal()
        .with_routes(routing.into())
        .connect();

    info!("adding addrs");
    pair.add_nat_traversal_address(Server, SimpleFirewallRouting::SERVER_FW_ADDR)?;
    // By adding a dummy address the client can start NAT traversal but does not advertise
    // its real public interface, thus emulating a hard NAT. Choose the last addr in the
    // client subnet.
    let dummy_addr: SocketAddr = "[::1:ffff]:1".parse()?;
    pair.add_nat_traversal_address(Client, dummy_addr)?;
    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(
        event,
        Event::NatTraversal(n0_nat_traversal::Event::AddressAdded(_))
    );

    info!("init NAT traversal");
    pair.initiate_nat_traversal_round(Client)?;

    // Ensure we have no more events queued
    assert_matches!(pair.poll(Client), None);
    assert_matches!(pair.poll(Server), None);

    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    let event = pair.poll(Server).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    Ok(())
}

/// Tests a "very easy NAT" for the client with a "hard NAT" for the server.
///
/// Here "very easy NAT" is an EIM+EIF NAT. The port is opened by the QAD probe. "hard NAT"
/// is an EDM NAT.
#[test]
fn test_hard_nat_server_opens_path() -> TestResult {
    let _guard = subscribe();
    let mut routing = SimpleFirewallRouting::new();
    // By configuring the client side to be open it emulates an EIM+EIF NAT: the QAD probe
    // already opened the firewall.
    routing.client_firewall_open = true;
    let mut pair = ConnPair::builder()
        .enable_multipath()
        .enable_nat_traversal()
        .with_routes(routing.into())
        .connect();

    info!("adding addrs");
    // By adding a dummy address the client can start NAT traversal but does not advertise
    // its real public interface, thus emulating a hard NAT. Choose the last addr in the
    // server subnet.
    let dummy_addr: SocketAddr = "[::2:ffff]:1".parse()?;
    pair.add_nat_traversal_address(Server, dummy_addr)?;
    pair.add_nat_traversal_address(Client, SimpleFirewallRouting::CLIENT_FW_ADDR)?;
    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(
        event,
        Event::NatTraversal(n0_nat_traversal::Event::AddressAdded(_))
    );

    info!("init NAT traversal");
    pair.initiate_nat_traversal_round(Client)?;

    // Ensure we have no more events queued
    assert_matches!(pair.poll(Client), None);
    assert_matches!(pair.poll(Server), None);

    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    let event = pair.poll(Server).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    Ok(())
}

/// If the client is not allowed to migrate, it should still be allowed to send NAT
/// traversal probes and be able to hole-punch.
#[test]
fn test_peer_may_probe() -> TestResult {
    let _guard = subscribe();

    let builder = ConnPair::builder()
        .enable_multipath()
        .enable_nat_traversal()
        .disable_mtud_discovery()
        .with_routes(SimpleFirewallRouting::new().into());
    let server_cfg = ServerConfig {
        transport: Arc::new(builder.server_transport_cfg.clone()),
        migration: false,
        ..server_config()
    };
    let mut pair = builder.with_server_cfg(server_cfg).connect();

    pair.add_nat_traversal_address(Server, SimpleFirewallRouting::SERVER_FW_ADDR)?;
    pair.add_nat_traversal_address(Client, SimpleFirewallRouting::CLIENT_FW_ADDR)?;
    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(
        event,
        Event::NatTraversal(n0_nat_traversal::Event::AddressAdded(_))
    );

    info!("init NAT traversal");
    pair.initiate_nat_traversal_round(Client)?;

    // Ensure we have no more events queued
    assert_matches!(pair.poll(Client), None);
    assert_matches!(pair.poll(Server), None);

    pair.drive();

    let event = pair.poll(Client).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    let event = pair.poll(Server).expect("should have event");
    assert_matches!(event, Event::Path(PathEvent::Established { .. }));

    Ok(())
}

#[test]
fn on_path_challenge_lost_backoff() {
    let _guard = subscribe();

    let mut pair = ConnPair::default();

    // We use two helpers so we can "skip over" unrelated stopping points from `next_wakeup`

    /// Attempts to drive the client until it has sent the expected amount of path challenges.
    ///
    /// Tries for a maximum of 10 iterations. Panics if that fails.
    fn drive_client_until_challenge_sent(pair: &mut ConnPair, expected_path_challenges_sent: u64) {
        for _ in 0..10 {
            pair.drive_client();
            if pair.stats(Client).frame_tx.path_challenge == expected_path_challenges_sent {
                return;
            }
            pair.time = pair
                .client
                .next_wakeup()
                .expect("couldn't drive client forward");
            info!("advancing to {:?} for client", pair.time - pair.epoch);
        }
        panic!(
            "client never sent PATH_CHALLENGE #{}, actual: {}",
            expected_path_challenges_sent,
            pair.stats(Client).frame_tx.path_challenge
        );
    }

    /// Attempts to drive the server until it has received the expected amount of path challenges.
    ///
    /// Tries for a maximum of 10 iterations. Panics if that fails.
    fn drive_server_until_challenge_received(
        pair: &mut ConnPair,
        expected_path_challenges_received: u64,
    ) {
        for _ in 0..10 {
            // attempt to drive the server until it receives the PATH_CHALLENGE and sends a PATH_RESPONSE
            pair.time = pair
                .server
                .next_wakeup()
                .expect("couldn't drive server forward");
            info!("advancing to {:?} for server", pair.time - pair.epoch);
            pair.drive_server();
            if pair.stats(Server).frame_rx.path_challenge == expected_path_challenges_received
                && pair.stats(Server).frame_tx.path_response == expected_path_challenges_received
            {
                return;
            }
        }
        panic!(
            "server never received PATH_CHALLENGE #{}, actual: {}",
            expected_path_challenges_received,
            pair.stats(Server).frame_rx.path_challenge
        );
    }

    pair.conn_mut(Client).trigger_path_validation();

    // Kickstart the process once to get a reference point for the last_challenge_sent
    drive_client_until_challenge_sent(&mut pair, 1);
    let mut last_challenge_send = pair.time;
    let mut last_duration = Duration::ZERO;

    const MAX_DURATION: Duration = Duration::from_secs(2); // equivalent to MAX_PTO_INTERVAL
    const MAX_ITERS: u64 = MAX_DURATION.as_millis().ilog2() as u64 + 2;

    for i in 1..=MAX_ITERS {
        drive_server_until_challenge_received(&mut pair, i);
        pair.client.inbound.clear(); // we drop the client-inbound PATH_RESPONSE
        info!("dropped client inbound");

        drive_client_until_challenge_sent(&mut pair, i + 1);
        let time = pair.time.duration_since(last_challenge_send);
        info!(?time, ?last_duration, "time since last PATH_CHALLENGE send");
        assert!(
            time >= last_duration,
            "duration between PATH_CHALLENGE sends must be monotonically increasing (backing off)"
        );
        assert!(
            time <= MAX_DURATION,
            "duration between PATH_CHALLENGE sends must be bound to a maximum of 2s"
        );
        if i == MAX_ITERS {
            assert_eq!(time, MAX_DURATION);
        }
        last_duration = time;
        last_challenge_send = pair.time;
    }

    // Now we stop dropping the client inbound once and the backoff should return back to normal:

    drive_server_until_challenge_received(&mut pair, MAX_ITERS + 1);
    pair.drive(); // Ensure the client fully processes the PATH_RESPONSE this time.
    info!("client should have processed PATH_RESPONSE");

    // The next time challenges are sent, the backoff should be reset.

    pair.conn_mut(Client).trigger_path_validation();
    drive_client_until_challenge_sent(&mut pair, MAX_ITERS + 2);
    last_challenge_send = pair.time;
    drive_server_until_challenge_received(&mut pair, MAX_ITERS + 2);
    pair.client.inbound.clear(); // we drop the client-inbound PATH_RESPONSE
    info!("dropped client inbound");
    drive_client_until_challenge_sent(&mut pair, MAX_ITERS + 3);
    let duration = pair.time.duration_since(last_challenge_send);
    assert_eq!(duration, Duration::from_millis(1));
}

#[test]
fn paths_blocked_retransmission() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    for _ in 1..MAX_PATHS {
        pair.open_path(
            Client,
            FourTuple::from_remote(server_addr),
            PathStatus::Available,
        )?;
    }
    pair.drive_client(); // Open all the paths we are allowed to open
    pair.drive_server(); // Let the server process all these newly opened paths
    pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )
    .expect_err("expected PathError::MaxPathIdReached");
    pair.drive_client(); // Let the client produce the PATHS_BLOCKED frame
    assert_eq!(pair.stats(Client).frame_tx.paths_blocked, 1);
    pair.server.inbound.clear(); // We drop the PATHS_BLOCKED frame
    pair.drive();
    assert_eq!(pair.stats(Client).frame_tx.paths_blocked, 2);
    Ok(())
}

/// This test used to generate a PROTOCOL_VIOLATION error from just packet loss and delayed packets.
///
/// The problem was receiving a PATH_CIDS_BLOCKED frame with path_id=1 and next_seq=1 when the server
/// side had already abandoned and discarded path 1.
/// In that case, we assumed the other side would violate the protocol, whereas in reality it's just
/// a (very) delayed packet.
///
/// The fix was to properly check if the path was already abandoned that the PATH_CIDS_BLOCKED frame
/// referred to.
#[test]
fn regression_delayed_path_cids_blocked() -> TestResult {
    let _guard = subscribe();

    let (mut pair, client_cfg) = ConnPair::builder().enable_multipath().build_pair();
    info!("connecting");
    let client_ch = pair.begin_connect(client_cfg);
    pair.drive_client(); // Client sends Initial
    pair.drive_server(); // Server receives Initial, sends Handshake
    pair.drive_client(); // Client receives Handshake, sends handshake confirmed
    pair.drive_server(); // Server receives handshake confirmed, sends PATH_NEW_CONNECTION_ID and confirms handshake itself
    // Capture the server's PATH_NEW_CONNECTION_ID frames so the client generates a PATH_CIDS_BLOCKED frame on the next open_path call.
    // This only works, because the server's outbound packet is constructed inefficiently:
    // The PATH_NEW_CONNECTION_ID frames should *actually* be coaleced together with the server's handshake response instead of
    // being put into a separate datagram. See also <https://github.com/n0-computer/noq/issues/66>
    let captured_server_cids = pair.client.inbound.pop_back().unwrap();
    pair.drive_client(); // Client receives confirmed handshake, but not PATH_NEW_CONNECTION_ID frames
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);

    // Attempting to open a path on the client side will fail, because we're missing the CIDs for path 1 and more
    let mut pair = ConnPair::new(pair, client_ch, server_ch);
    let server_addr = pair.routes.public_server_addr();
    pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )
    .expect_err("expected RemoteCidsExhausted error");

    pair.drive_client(); // Client generates PATH_CIDS_BLOCKED
    // We intentionally drop the client's PATH_CIDS_BLOCKED frame.
    pair.server.inbound.pop_back().unwrap();
    // After the client has sent the PATH_CIDS_BLOCKED frame, we give it all the server's CIDs.
    pair.client.inbound.push_back(captured_server_cids);
    pair.drive_client(); // Client processes the delayed server's PATH_NEW_CONNECTION_ID

    info!("Skipping forward 80ms");
    pair.time += Duration::from_millis(80); // Trigger the client's loss detection timer for the PATH_CIDS_BLOCKED frame
    pair.drive_client(); // Client generates another PATH_CIDS_BLOCKED
    // This is now an encrypted datagram containing a PATH_CIDS_BLOCKED path_id=1 next_seq=1 frame.
    let captured_client_cids_blocked = pair.server.inbound.pop_back().unwrap();

    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive(); // Fully open the path on both ends
    pair.close_path(Client, path_id, 42u32.into())?;
    pair.drive(); // Fully process closing the path on both ends, including discarding path state

    // Now we send the delayed PATH_CIDS_BLOCKED frame, and it'll trigger a protocol violation
    pair.server.inbound.push_front(captured_client_cids_blocked);
    pair.drive();

    // The server must not close the connection over the stale frame.
    while let Some(event) = pair.poll(Server) {
        if let Event::ConnectionLost {
            reason: crate::ConnectionError::TransportError(error),
        } = event
        {
            assert_ne!(
                error.code,
                TransportErrorCode::PROTOCOL_VIOLATION,
                "stale PATH_CIDS_BLOCKED should not trigger PROTOCOL_VIOLATION: {}",
                error.reason
            );
        }
    }
    Ok(())
}

#[test]
fn regression_discarded_path_stats_are_up_to_date() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();

    let server_addr = pair.routes.public_server_addr();
    let path_id = pair.open_path(
        Client,
        FourTuple::from_remote(server_addr),
        PathStatus::Available,
    )?;
    pair.drive();

    // Drain establishment events.
    while pair.poll(Client).is_some() {}
    while pair.poll(Server).is_some() {}

    // Close the path and drive until both sides discard it.
    pair.close_path(Client, path_id, 0u8.into())?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned { id, .. })) if id == path_id
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Abandoned { id, .. })) if id == path_id
    );

    pair.drive();

    let discarded_stats = assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Discarded { id, path_stats })) if id == path_id
        => *path_stats
    );

    // After a full handshake + MTU probing on the second path, these must be non-zero.
    assert_ne!(discarded_stats.cwnd, 0);
    assert_ne!(discarded_stats.current_mtu, 0);

    Ok(())
}
