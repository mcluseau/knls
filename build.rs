use std::process::Command;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    let git_commit = String::from_utf8(output.stdout)?;
    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);
    Ok(())
}
