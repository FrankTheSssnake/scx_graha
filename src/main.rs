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


// default time slice
const SLICE_NS: u64 = 5_000_000;


struct GrahaScheduler<'a> {
    bpf: BpfScheduler<'a>
}

impl<'a> GrahaScheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let open_opts = LibbpfOpts::default();
        let bpf = BpfScheduler::init(
            open_object,
            open_opts.clone().into_bpf_open_opts(),
            0,              // buffer size of exit info
            false,          // include all tasks
            true,           // debug mode
            true,           // use idle cpus
            SLICE_NS,       // default time slice
            "graha"
        )?;

        Ok(Self { bpf })
    }

    // TODO
    fn dispatch_tasks(&mut self) {
        let waiting = *self.bpf.nr_queued_mut();

        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            let mut dispatched_task = DispatchedTask::new(&task);

            // calculate best idle cpu
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            dispatched_task.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };

            dispatched_task.slice_ns = SLICE_NS / (waiting + 1);

            self.bpf.dispatch_task(&dispatched_task).unwrap();
        }

        // sleep
        self.bpf.notify_complete(0);
    }

    fn print_stats(&mut self) {
        // Internal scx_rustland_core statistics.
        let nr_user_dispatches = *self.bpf.nr_user_dispatches_mut();
        let nr_kernel_dispatches = *self.bpf.nr_kernel_dispatches_mut();
        let nr_cancel_dispatches = *self.bpf.nr_cancel_dispatches_mut();
        let nr_bounce_dispatches = *self.bpf.nr_bounce_dispatches_mut();
        let nr_failed_dispatches = *self.bpf.nr_failed_dispatches_mut();
        let nr_sched_congested = *self.bpf.nr_sched_congested_mut();

        println!(
            "user={} kernel={} cancel={} bounce={} fail={} cong={}",
            nr_user_dispatches,
            nr_kernel_dispatches,
            nr_cancel_dispatches,
            nr_bounce_dispatches,
            nr_failed_dispatches,
            nr_sched_congested,
        );
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        while !self.bpf.exited() {
            self.dispatch_tasks();

            let current_ts = Self::now();
            if current_ts > prev_ts {
                self.print_stats();
                prev_ts = current_ts
            }
        }

        self.bpf.shutdown_and_report()
    }
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

