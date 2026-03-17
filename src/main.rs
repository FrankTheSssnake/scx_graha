mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;


mod bpf;
use std::mem::MaybeUninit;
use std::time::SystemTime;

use anyhow::Result;
use bpf::*;
use libbpf_rs::OpenObject;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::UserExitInfo;


struct GrahaScheduler<'a> {
    bpf: BpfScheduler<'a>;
}

impl<'a> GrahaScheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self>;

    fn dispatch_tasks(&mut self);

    fn print_stats(&mut self);

    fn now() -> u64;

    fn run(&mut self) -> Result<UserExitInfo>;
}


fn print_warning() {
    let warning = r#"
**************************************************************************

WARNING: The purpose of scx_graha is to provide a fun, quirky scheduler
implementation based on scx_rustland_core, and it is not intended for
use in production environments. If you want to run a scheduler that makes
decisions in user space, it is recommended to use *scx_rustland* instead.

Please do not open GitHub issues in the event of poor performance, or
scheduler eviction due to a runnable task timeout. However, if running this
scheduler results in a system crash or the entire system becoming unresponsive,
please open a GitHub issue.

**************************************************************************"#;

    println!("{}", warning);
}


fn main() -> Result<()> {
    print_warning();

    // Initialise and use the GrahaScheduler
    let mut open_object = MaybeUninit::uninit();
    
    loop {
        let mut sched: GrahaScheduler = GrahaScheduler::init(&mut open_object)?;
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}

