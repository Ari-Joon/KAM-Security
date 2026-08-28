//! A weekly check, run by Windows rather than by us.
//!
//! # Why there is no timer in this program
//!
//! The agent costs nothing while nobody is asking it anything: two threads,
//! about a megabyte of private memory, and no measurable CPU since it started,
//! because it sits blocked in `ConnectNamedPipe`. A thread that woke every few
//! minutes to see whether it was time yet would throw that away for a feature
//! nobody would notice was running.
//!
//! So the schedule lives in the Task Scheduler, which is the part of Windows
//! whose whole job this is. It costs nothing when it is not running, it already
//! knows how to hold a run back until the machine is idle and on mains power,
//! and it catches up a run that was missed because the machine was off. None of
//! that would be worth writing again badly.
//!
//! # It is off until asked for, and it says so about itself
//!
//! This product reports on what starts itself at boot. Quietly adding itself to
//! that list would be grotesque, so nothing is registered until somebody turns
//! it on, and when they do, the task appears in this product's own survey of
//! what starts itself, under this product's own name.
//!
//! # It runs as the person who turned it on, with no special rights
//!
//! Not as SYSTEM. Half of what a check looks at is per-user -- the `Run` keys
//! in your hive, your Startup folder, your AppData -- and a check running as
//! SYSTEM would examine an account nobody has ever installed anything into and
//! report that everything was fine.
//!
//! It is not elevated either. The task starts a process that asks the service
//! for a check and prints the answer; the service already has the rights and
//! already knows how to identify its caller. So the thing being added to
//! somebody's machine runs as them, with their ordinary permissions, which is a
//! much smaller thing to ask than something elevated on a timer. An interactive
//! logon type means it only runs while somebody is signed in, which is the only
//! time the answer matters anyway.

use kam_core::{Error, Result};
use serde::{Deserialize, Serialize};
use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ITaskFolder, ITaskService, IWeeklyTrigger, TaskScheduler, TASK_ACTION_EXEC,
    TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_LUA, TASK_TRIGGER_WEEKLY,
};
use windows::Win32::System::Variant::VARIANT;

/// The folder this product's tasks live in, so they are obvious in Task
/// Scheduler and can never be confused with anything Windows registered.
const FOLDER: &str = "\\KAM Security";

/// The task's name inside that folder.
const TASK: &str = "Weekly check";

/// Full path, which is what most of the API wants.
const FULL_PATH: &str = "\\KAM Security\\Weekly check";

/// The argument the task passes, and the agent recognises.
pub const CHECK_ARGUMENT: &str = "--check";

/// What the schedule is currently set to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub enabled: bool,
    /// Which day it runs, as a name. `None` when nothing is registered.
    pub day: Option<String>,
    /// Local time of day, `HH:MM`.
    pub at: Option<String>,
    /// The account it runs as, when one is recorded.
    pub account: Option<String>,
    /// Path of the program the task starts, so what was registered can be seen
    /// rather than taken on trust.
    pub command: Option<String>,
}

impl Schedule {
    fn off() -> Self {
        Self {
            enabled: false,
            day: None,
            at: None,
            account: None,
            command: None,
        }
    }
}

/// Days of the week, in the bit order the trigger uses.
const DAYS: [(&str, u16); 7] = [
    ("Sunday", 0x01),
    ("Monday", 0x02),
    ("Tuesday", 0x04),
    ("Wednesday", 0x08),
    ("Thursday", 0x10),
    ("Friday", 0x20),
    ("Saturday", 0x40),
];

fn day_name(mask: u16) -> Option<String> {
    DAYS.iter()
        .find(|(_, bit)| mask & bit != 0)
        .map(|(name, _)| (*name).to_owned())
}

/// COM apartment held for the length of one call.
struct ComGuard;

impl ComGuard {
    fn enter() -> Self {
        let outcome = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        // Already initialised in another mode is fine; every call below works
        // either way. Uninitialising is still correct, because this thread's
        // count went up regardless.
        let _ = outcome;
        Self
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn service() -> Result<ITaskService> {
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| Error::Privileged(format!("no task scheduler: {error}")))?;

    // Empty variants mean "this machine, as me", which is the only connection
    // this ever wants.
    unsafe {
        service.Connect(
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
        )
    }
    .map_err(|error| Error::Privileged(format!("could not reach the task scheduler: {error}")))?;

    Ok(service)
}

/// Our own folder, created if it is not there yet.
fn folder(service: &ITaskService, create: bool) -> Result<ITaskFolder> {
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }
        .map_err(|error| Error::Privileged(format!("no task folder: {error}")))?;

    if let Ok(existing) = unsafe { service.GetFolder(&BSTR::from(FOLDER)) } {
        return Ok(existing);
    }
    if !create {
        return Err(Error::Refused("no schedule is registered".to_owned()));
    }

    unsafe { root.CreateFolder(&BSTR::from(FOLDER), &VARIANT::default()) }
        .map_err(|error| Error::Privileged(format!("could not create the task folder: {error}")))
}

/// What is registered right now.
pub fn current() -> Schedule {
    let _com = ComGuard::enter();

    let Ok(service) = service() else {
        return Schedule::off();
    };
    let Ok(folder) = folder(&service, false) else {
        return Schedule::off();
    };
    let Ok(task) = (unsafe { folder.GetTask(&BSTR::from(TASK)) }) else {
        return Schedule::off();
    };

    // A task that exists but is disabled is not a schedule, and saying it is
    // would be the sort of comforting lie this whole product exists to avoid.
    let enabled = unsafe { task.Enabled() }.is_ok_and(|value| value == VARIANT_TRUE);

    let Ok(definition) = (unsafe { task.Definition() }) else {
        return Schedule::off();
    };

    let mut schedule = Schedule {
        enabled,
        day: None,
        at: None,
        account: None,
        command: None,
    };

    if let Ok(principal) = unsafe { definition.Principal() } {
        let mut account = BSTR::default();
        if unsafe { principal.UserId(&mut account) }.is_ok() && !account.is_empty() {
            schedule.account = Some(account.to_string());
        }
    }

    if let Ok(actions) = unsafe { definition.Actions() } {
        // One action, at index one: this collection is one-based.
        if let Ok(action) = unsafe { actions.get_Item(1) } {
            if let Ok(exec) = action.cast::<IExecAction>() {
                let mut path = BSTR::default();
                if unsafe { exec.Path(&mut path) }.is_ok() && !path.is_empty() {
                    schedule.command = Some(path.to_string());
                }
            }
        }
    }

    if let Ok(triggers) = unsafe { definition.Triggers() } {
        if let Ok(trigger) = unsafe { triggers.get_Item(1) } {
            let mut start = BSTR::default();
            if unsafe { trigger.StartBoundary(&mut start) }.is_ok() {
                // ISO 8601 local time: 2026-08-30T03:00:00. The clock face is
                // the only part worth showing.
                let text = start.to_string();
                schedule.at = text
                    .split('T')
                    .nth(1)
                    .map(|time| time[..5.min(time.len())].to_owned());
            }
            if let Ok(weekly) = trigger.cast::<IWeeklyTrigger>() {
                let mut mask = 0_i16;
                if unsafe { weekly.DaysOfWeek(&mut mask) }.is_ok() {
                    schedule.day = day_name(mask as u16);
                }
            }
        }
    }

    schedule
}

/// Register the weekly check, or replace what is registered.
///
/// `program` is the full path of the executable to run, and `account` the user
/// it runs as. Both come from the agent, never from a client: this creates
/// something that runs elevated on a timer, and a caller that could name the
/// program would have named a way to run anything.
pub fn enable(program: &str, account: &str, day: &str, hour: u8) -> Result<Schedule> {
    let _com = ComGuard::enter();
    let service = service()?;
    let folder = folder(&service, true)?;

    let definition = unsafe { service.NewTask(0) }
        .map_err(|error| Error::Privileged(format!("could not start a task: {error}")))?;

    let (day_name, day_mask) = DAYS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(day))
        .copied()
        .unwrap_or(("Sunday", 0x01));

    unsafe {
        let info = definition
            .RegistrationInfo()
            .map_err(|error| Error::Privileged(format!("no registration info: {error}")))?;
        info.SetAuthor(&BSTR::from("KAM Security"))
            .map_err(|error| Error::Privileged(format!("could not set the author: {error}")))?;
        info.SetDescription(&BSTR::from(
            "Checks Windows Defender, the firewall, and what starts itself. \
             Registered by KAM Security, and removed when the check is turned off.",
        ))
        .map_err(|error| Error::Privileged(format!("could not describe the task: {error}")))?;

        // What makes this cost nothing anybody would notice.
        let settings = definition
            .Settings()
            .map_err(|error| Error::Privileged(format!("no settings: {error}")))?;
        settings
            .SetDisallowStartIfOnBatteries(VARIANT_TRUE)
            .and_then(|()| settings.SetStopIfGoingOnBatteries(VARIANT_TRUE))
            // A run missed because the machine was off happens next time it is
            // on, rather than being skipped until the following week.
            .and_then(|()| settings.SetStartWhenAvailable(VARIANT_TRUE))
            // Half an hour is generous for a check that takes seconds, and it
            // guarantees a wedged run cannot sit there forever.
            .and_then(|()| settings.SetExecutionTimeLimit(&BSTR::from("PT30M")))
            .map_err(|error| Error::Privileged(format!("could not set the settings: {error}")))?;

        let triggers = definition
            .Triggers()
            .map_err(|error| Error::Privileged(format!("no triggers: {error}")))?;
        let trigger = triggers
            .Create(TASK_TRIGGER_WEEKLY)
            .map_err(|error| Error::Privileged(format!("could not add a trigger: {error}")))?;
        let weekly: IWeeklyTrigger = trigger
            .cast()
            .map_err(|error| Error::Privileged(format!("wrong trigger type: {error}")))?;
        weekly
            .SetDaysOfWeek(day_mask as i16)
            .and_then(|()| weekly.SetWeeksInterval(1))
            .map_err(|error| Error::Privileged(format!("could not set the day: {error}")))?;
        // The date is only a starting point for a weekly trigger; the time of
        // day is the part that matters, and it is local.
        weekly
            .SetStartBoundary(&BSTR::from(format!("2026-01-04T{hour:02}:00:00")))
            .map_err(|error| Error::Privileged(format!("could not set the time: {error}")))?;

        let actions = definition
            .Actions()
            .map_err(|error| Error::Privileged(format!("no actions: {error}")))?;
        let action = actions
            .Create(TASK_ACTION_EXEC)
            .map_err(|error| Error::Privileged(format!("could not add an action: {error}")))?;
        let exec: IExecAction = action
            .cast()
            .map_err(|error| Error::Privileged(format!("wrong action type: {error}")))?;
        exec.SetPath(&BSTR::from(program))
            .and_then(|()| exec.SetArguments(&BSTR::from(CHECK_ARGUMENT)))
            .map_err(|error| Error::Privileged(format!("could not set the program: {error}")))?;

        let principal = definition
            .Principal()
            .map_err(|error| Error::Privileged(format!("no principal: {error}")))?;
        principal
            .SetUserId(&BSTR::from(account))
            .and_then(|()| principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN))
            // Least privilege, deliberately. The work happens in the
            // service, which already has the rights; this process only asks.
            .and_then(|()| principal.SetRunLevel(TASK_RUNLEVEL_LUA))
            .map_err(|error| Error::Privileged(format!("could not set the account: {error}")))?;

        folder
            .RegisterTaskDefinition(
                &BSTR::from(TASK),
                &definition,
                TASK_CREATE_OR_UPDATE.0,
                &VARIANT::default(),
                &VARIANT::default(),
                TASK_LOGON_INTERACTIVE_TOKEN,
                &VARIANT::default(),
            )
            .map_err(|error| Error::Privileged(format!("could not register the task: {error}")))?;
    }

    tracing::info!(%day_name, hour, %account, "registered the weekly check");
    Ok(current())
}

/// Remove the task, and the folder with it if nothing else is in there.
///
/// Removing it completely rather than disabling it is the point: something a
/// person turned off should not still be sitting in Task Scheduler looking like
/// it might run.
pub fn disable() -> Result<()> {
    let _com = ComGuard::enter();
    let service = service()?;

    let Ok(folder) = folder(&service, false) else {
        // Nothing registered is the state being asked for.
        return Ok(());
    };

    unsafe { folder.DeleteTask(&BSTR::from(TASK), 0) }
        .map_err(|error| Error::Privileged(format!("could not remove the task: {error}")))?;

    // Tidy the folder away too, but only if it is empty: deleting one that
    // somebody had put something else into would be presumptuous.
    if let Ok(root) = unsafe { service.GetFolder(&BSTR::from("\\")) } {
        let empty = unsafe { folder.GetTasks(0) }
            .and_then(|tasks| unsafe { tasks.Count() })
            .map(|count| count == 0)
            .unwrap_or(false);
        if empty {
            let _ = unsafe { root.DeleteFolder(&BSTR::from(FOLDER), 0) };
        }
    }

    Ok(())
}

/// The path this product's own task is registered at.
///
/// Exposed so the survey of what starts itself can recognise its own entry and
/// say so, rather than reporting it as an unexplained scheduled task.
pub fn task_path() -> &'static str {
    FULL_PATH
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_day_has_exactly_one_bit_and_they_do_not_overlap() {
        let mut seen = 0_u16;
        for (name, bit) in DAYS {
            assert_eq!(bit.count_ones(), 1, "{name} is not a single bit");
            assert_eq!(seen & bit, 0, "{name} collides with an earlier day");
            seen |= bit;
        }
        assert_eq!(seen, 0x7F, "seven days should fill seven bits");
    }

    #[test]
    fn a_mask_reads_back_as_the_day_it_was_set_from() {
        for (name, bit) in DAYS {
            assert_eq!(day_name(bit).as_deref(), Some(name));
        }
        assert_eq!(day_name(0), None);
    }

    #[test]
    fn the_task_lives_in_a_folder_named_for_this_product() {
        // So it is obvious in Task Scheduler whose it is, and so removing it
        // can never reach anything else.
        assert!(FULL_PATH.starts_with(FOLDER));
        assert!(FULL_PATH.ends_with(TASK));
        assert!(FOLDER.contains("KAM Security"));
    }

    #[test]
    fn reading_the_schedule_works_whether_or_not_one_is_registered() {
        // Runs unprivileged in CI, where the answer is simply "nothing".
        let schedule = current();
        if !schedule.enabled {
            assert!(schedule.day.is_none() || schedule.at.is_some());
        }
    }

    #[test]
    #[ignore = "registers a real scheduled task; needs administrative rights"]
    fn a_schedule_can_be_registered_read_back_and_removed() {
        let program = std::env::current_exe().unwrap().display().to_string();
        let account = std::env::var("USERNAME").unwrap();

        let registered = enable(&program, &account, "Wednesday", 3).expect("could not register");
        assert!(registered.enabled);
        assert_eq!(registered.day.as_deref(), Some("Wednesday"));
        assert_eq!(registered.at.as_deref(), Some("03:00"));
        assert_eq!(registered.command.as_deref(), Some(program.as_str()));

        disable().expect("could not remove");
        assert!(!current().enabled, "the task is still registered");
        // And removing something already gone is not an error.
        disable().expect("removing nothing should be fine");
    }
}
