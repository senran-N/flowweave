use flowweave_lab::{LabResult, print_basic_report, run_basic_lab, verify_basic_report};

#[tokio::main]
async fn main() -> LabResult<()> {
    let report = run_basic_lab().await?;
    verify_basic_report(&report)?;
    print_basic_report(&report);
    Ok(())
}
