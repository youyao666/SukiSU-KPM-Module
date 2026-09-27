// adb_client dependency removed (upstream repo deleted); magica late-load via adb disabled.
use anyhow::Result;

pub fn run(_port: u16, _package_name: &String, _allow_shell: bool) -> Result<()> {
    anyhow::bail!("magica disabled in this build (adb_client dependency removed)")
}
