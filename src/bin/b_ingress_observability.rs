use std::{env, io};

use flowweave_lab::{
    LabResult, run_b_ingress_observability_controller, run_b_ingress_observability_receiver,
    run_b_ingress_shaper_calibration,
};

fn main() -> LabResult<()> {
    if env::args().nth(1).as_deref() == Some("receiver") {
        return run_b_ingress_observability_receiver();
    }
    let receiver_pid = env::var("FLOWWEAVE_B_INGRESS_RECEIVER_PID")?
        .parse::<u32>()
        .map_err(|error| io::Error::other(format!("invalid receiver pid: {error}")))?;
    if env::args().nth(1).as_deref() == Some("calibrate") {
        return run_b_ingress_shaper_calibration(receiver_pid);
    }
    let report = run_b_ingress_observability_controller(receiver_pid)?;
    if !report.stage_pass {
        return Err(io::Error::other(
            "B separated ingress observability v1 failed its preregistered gate",
        )
        .into());
    }
    Ok(())
}
