//! The processes inside a sandboxed Session's container, for the background-process check
//! (#5858). One exec runs a constant script over the container's `/proc`. For each process it
//! reports only whether its environment carries this launch's marker, an earlier launch's, or
//! none; the environment itself never leaves the container.

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;

use super::ContainerExecutionSnapshot;

/// Bounds the census exec, as the host census bounds its process scan.
pub(crate) const CENSUS_TIMEOUT: Duration = Duration::from_secs(5);

/// `$1` is the launch's id, `$2` the proc root (`/proc` unless a test passes one). Prints
/// `up <seconds>`, then `<launch> <stat> <cmdline>` per process with the last two in base64,
/// then `end`, so a cut-off listing is told from a short one. The marker is
/// [`crate::hooks::SESSION_SOURCE_ENV`], which every sandboxed launch exports with its id.
pub(crate) const CENSUS_SCRIPT: &str = r#"r=${2:-/proc}
read -r up _ < "$r/uptime" || exit 3
printf 'up %s\n' "$up"
for d in "$r"/[0-9]*; do
  s=$(base64 -w0 < "$d/stat" 2>/dev/null) && [ -n "$s" ] || continue
  a=$(base64 -w0 < "$d/cmdline" 2>/dev/null)
  if grep -qzxF -- "AOE_SESSION_SOURCE=$1" "$d/environ" 2>/dev/null; then l=current
  elif grep -qz -- '^AOE_SESSION_SOURCE=' "$d/environ" 2>/dev/null; then l=earlier
  else l=none
  fi
  printf '%s %s %s\n' "$l" "$s" "$a"
done
printf 'end\n'
"#;

/// Bounds the stop exec: its TERM and KILL waits plus the scans between them.
pub(crate) const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// `$1` is the launch's id, `$2` the proc root, then `pid:start` words for the processes of
/// earlier launches the caller confirmed. Signals every process carrying this launch's marker,
/// and an earlier launch's only when its pid and start time both still match a word, so a
/// recycled pid is never signalled. TERM first, KILL for what is left after about 2 s; every
/// pass reads `/proc` again. Prints `survived <n>`.
pub(crate) const STOP_SCRIPT: &str = r#"l=$1 r=$2
shift 2
pairs=" $* "
st() {
  s=$(cat "$r/$1/stat" 2>/dev/null) || return 1
  set -- ${s##*") "}
  [ "$1" != Z ] && [ "$1" != X ] && printf '%s' "${20}"
}
pick() {
  for d in "$r"/[0-9]*; do
    p=${d##*/}
    if grep -qzxF -- "AOE_SESSION_SOURCE=$l" "$d/environ" 2>/dev/null; then
      st "$p" > /dev/null && echo "$p"
    elif grep -qz -- '^AOE_SESSION_SOURCE=' "$d/environ" 2>/dev/null; then
      t=$(st "$p") || continue
      case $pairs in *" $p:$t "*) echo "$p" ;; esac
    fi
  done
}
wait_gone() {
  i=0
  while [ $i -lt "$1" ] && [ -n "$(pick)" ]; do
    sleep 0.2 2>/dev/null || sleep 1
    i=$((i + 1))
  done
}
v=$(pick)
[ -n "$v" ] && kill -TERM $v 2>/dev/null
wait_gone 10
v=$(pick)
[ -n "$v" ] && kill -KILL $v 2>/dev/null
wait_gone 5
n=0
for p in $(pick); do n=$((n + 1)); done
printf 'survived %s\n' "$n"
"#;

/// Stops this launch's processes in the container, and the `earlier` ones (pid and start time,
/// both the container's) a caller confirmed. An error when the exec fails or any survive.
pub(crate) fn stop(
    container: &ContainerExecutionSnapshot,
    launch_id: &str,
    earlier: &[(u32, u64)],
) -> Result<()> {
    let mut args = ["/bin/sh", "-c", STOP_SCRIPT, "sh", launch_id, "/proc"]
        .map(String::from)
        .to_vec();
    args.extend(earlier.iter().map(|(pid, start)| format!("{pid}:{start}")));
    let output = container
        .runtime
        .exec_output(&container.id, &args, STOP_TIMEOUT)?;
    ensure!(
        output.status.success(),
        "container stop exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let survived: usize = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("survived "))
        .context("container stop gave no count")?
        .trim()
        .parse()
        .context("container stop count")?;
    ensure!(
        survived == 0,
        "{survived} processes of the old launch survived the container stop"
    );
    Ok(())
}

/// Which launch a container process belongs to, by the marker it inherited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Launch {
    Current,
    Earlier,
    /// No marker: another exec (a container terminal, a login helper), or one that cleared its
    /// environment.
    Unmarked,
}

/// A live process inside the container. `pid` and `parent` are the container's own pids,
/// unrelated to the host's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerProcess {
    pub pid: u32,
    pub parent: u32,
    /// Start time in clock ticks since the container's kernel booted.
    pub start: u64,
    pub elapsed_secs: u64,
    pub argv: Vec<String>,
    pub launch: Launch,
}

/// The container's live processes, through the runtime endpoint the launch used.
pub(crate) fn read(
    container: &ContainerExecutionSnapshot,
    launch_id: &str,
) -> Result<Vec<ContainerProcess>> {
    let args = ["/bin/sh", "-c", CENSUS_SCRIPT, "sh", launch_id].map(String::from);
    let output = container
        .runtime
        .exec_output(&container.id, &args, CENSUS_TIMEOUT)?;
    ensure!(
        output.status.success(),
        "container census exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    parse(&String::from_utf8(output.stdout).context("container census output")?)
}

/// `/proc` start times are in USER_HZ, which Linux fixes at 100 for userspace.
const TICKS_PER_SEC: f64 = 100.0;

fn parse(output: &str) -> Result<Vec<ContainerProcess>> {
    let mut lines = output.lines();
    let up: f64 = lines
        .next()
        .and_then(|line| line.strip_prefix("up "))
        .context("container census has no uptime")?
        .parse()
        .context("container uptime")?;
    let decode = |field: Option<&str>| {
        base64::engine::general_purpose::STANDARD
            .decode(field.unwrap_or_default())
            .context("container census field")
    };
    let mut found = Vec::new();
    for line in lines {
        if line == "end" {
            return Ok(found);
        }
        let mut fields = line.splitn(3, ' ');
        let launch = match fields.next() {
            Some("current") => Launch::Current,
            Some("earlier") => Launch::Earlier,
            Some("none") => Launch::Unmarked,
            other => bail!("container census line starts {other:?}"),
        };
        let stat = String::from_utf8_lossy(&decode(fields.next())?).into_owned();
        let cmdline = decode(fields.next())?;
        let (pid, rest) = stat
            .split_once(" (")
            .and_then(|(pid, rest)| Some((pid, rest.rsplit_once(") ")?.1)))
            .context("container process stat")?;
        let stat: Vec<&str> = rest.split_whitespace().collect();
        // A zombie can't be signalled and has no command line; it isn't a running process.
        if matches!(stat.first(), Some(&"Z" | &"X")) {
            continue;
        }
        let start: u64 = stat.get(19).context("container process start")?.parse()?;
        found.push(ContainerProcess {
            pid: pid.parse().context("container process pid")?,
            parent: stat.get(1).context("container process parent")?.parse()?,
            start,
            elapsed_secs: (up - start as f64 / TICKS_PER_SEC).max(0.0) as u64,
            argv: cmdline
                .split(|byte| *byte == 0)
                .filter(|arg| !arg.is_empty())
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect(),
            launch,
        });
    }
    bail!("container census ended early")
}

/// A runtime program for tests: it writes its argv, NUL-separated, to `dir/argv`, then runs
/// `tail` as shell with the same arguments.
#[cfg(test)]
pub(crate) fn fake_container(
    dir: &std::path::Path,
    name: &str,
    tail: &str,
) -> ContainerExecutionSnapshot {
    use std::os::unix::fs::PermissionsExt;

    let program = dir.join(name);
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\0' \"$a\"; done > '{}'\n{tail}\n",
            dir.join("argv").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    ContainerExecutionSnapshot {
        runtime: super::RuntimeExecutionSnapshot {
            kind: crate::session::ContainerRuntimeName::Docker,
            program,
            cwd: dir.to_path_buf(),
            endpoint: String::new(),
            local_mounts: true,
            routing: Vec::new(),
            global_arguments: Vec::new(),
        },
        name: "aoe-test".into(),
        id: "container-id".into(),
        mounts: Vec::new(),
        shadow_mounts: Vec::new(),
    }
}

/// The argv [`fake_container`] last recorded in `dir`.
#[cfg(test)]
pub(crate) fn recorded_argv(dir: &std::path::Path) -> Vec<String> {
    std::fs::read(dir.join("argv"))
        .unwrap()
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake `/proc` for the script: one directory per process, with `stat`, `cmdline` and
    /// `environ` as the kernel lays them out.
    struct FakeProc(tempfile::TempDir);

    impl FakeProc {
        fn new(uptime: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("uptime"), format!("{uptime} 0.00\n")).unwrap();
            Self(dir)
        }

        fn process(
            &self,
            pid: u32,
            parent: u32,
            state: &str,
            start: u64,
            argv: &[&str],
            env: &[&str],
        ) {
            let dir = self.0.path().join(pid.to_string());
            std::fs::create_dir(&dir).unwrap();
            let comm = argv
                .first()
                .map_or("", |arg| arg.rsplit('/').next().unwrap_or(arg));
            // Fields after `(comm)`: state, ppid, then 17 more before starttime.
            let filler = ["0"; 17].join(" ");
            std::fs::write(
                dir.join("stat"),
                format!("{pid} ({comm}) {state} {parent} {filler} {start} 0 0\n"),
            )
            .unwrap();
            let nul = |words: &[&str]| {
                words
                    .iter()
                    .map(|word| format!("{word}\0"))
                    .collect::<String>()
            };
            std::fs::write(dir.join("cmdline"), nul(argv)).unwrap();
            std::fs::write(dir.join("environ"), nul(env)).unwrap();
        }

        fn run(&self, launch_id: &str) -> String {
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", CENSUS_SCRIPT, "sh", launch_id])
                .arg(self.0.path())
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            String::from_utf8(output.stdout).unwrap()
        }
    }

    /// The probe's shape (Katie, 2026-11-23): the current Agent, a backgrounded `sleep` already
    /// reparented to the container's init, an earlier launch's orphaned Agent, a container
    /// terminal, and a zombie. Each gets its launch, and nothing from an environment is printed.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_script_reports_each_process_s_launch_and_nothing_of_its_environment() {
        let proc = FakeProc::new("1000.50");
        let current = ["SECRET_TOKEN=s3cret", "AOE_SESSION_SOURCE=launch-2"];
        let earlier = ["SECRET_TOKEN=s3cret", "AOE_SESSION_SOURCE=launch-1"];
        proc.process(1, 0, "S", 100, &["sleep", "infinity"], &[]);
        proc.process(60, 0, "S", 90_000, &["claude", "--resume", "x"], &current);
        proc.process(61, 1, "S", 90_500, &["sleep", "600"], &current);
        proc.process(
            124,
            1,
            "S",
            50_000,
            &["claude", "--session-id", "x"],
            &earlier,
        );
        proc.process(70, 0, "S", 95_000, &["/bin/bash"], &["TERM=xterm"]);
        proc.process(71, 60, "Z", 95_100, &[], &current);
        // Prefix of the current id: an earlier launch, never the current one.
        proc.process(
            80,
            1,
            "S",
            95_200,
            &["node"],
            &["AOE_SESSION_SOURCE=launch-22"],
        );

        let stdout = proc.run("launch-2");
        for leak in ["s3cret", "SECRET_TOKEN", "launch-1", "launch-2", "TERM"] {
            assert!(!stdout.contains(leak), "{leak} in {stdout}");
        }
        let mut found = parse(&stdout).unwrap();
        found.sort_by_key(|process| process.pid);
        let seen: Vec<_> = found
            .iter()
            .map(|p| {
                (
                    p.pid,
                    p.parent,
                    p.launch,
                    p.argv.first().map(String::as_str),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (1, 0, Launch::Unmarked, Some("sleep")),
                (60, 0, Launch::Current, Some("claude")),
                (61, 1, Launch::Current, Some("sleep")),
                (70, 0, Launch::Unmarked, Some("/bin/bash")),
                (80, 1, Launch::Earlier, Some("node")),
                (124, 1, Launch::Earlier, Some("claude")),
            ]
        );
        let sleep = &found[2];
        assert_eq!((sleep.start, sleep.elapsed_secs), (90_500, 95));
        assert_eq!(sleep.argv, ["sleep", "600"]);
    }

    /// The exec goes through the runtime program the launch recorded, with the script constant
    /// and the launch id a separate argument. A failing or garbled exec is an error.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_census_execs_the_constant_script_with_the_launch_as_an_argument() {
        let proc = FakeProc::new("1000.00");
        proc.process(
            60,
            0,
            "S",
            90_000,
            &["claude"],
            &["AOE_SESSION_SOURCE=launch-2"],
        );
        let bin = tempfile::tempdir().unwrap();
        let container = |name: &str, tail: &str| fake_container(bin.path(), name, tail);
        let runs = container(
            "runs",
            &format!("shift 2\nexec \"$@\" '{}'", proc.0.path().display()),
        );
        let found = read(&runs, "launch-2").unwrap();
        assert_eq!(
            found.iter().map(|p| (p.pid, p.launch)).collect::<Vec<_>>(),
            [(60, Launch::Current)]
        );
        let want = [
            "exec",
            "container-id",
            "/bin/sh",
            "-c",
            CENSUS_SCRIPT,
            "sh",
            "launch-2",
        ];
        assert_eq!(recorded_argv(bin.path()), want);

        for (name, tail) in [
            ("fails", "echo gone >&2; exit 1"),
            ("garbled", "echo garbage"),
        ] {
            assert!(read(&container(name, tail), "launch-2").is_err(), "{name}");
        }
    }

    /// The stop, on real processes: the script's proc root holds only this test's children, so
    /// nothing else on the machine is read or signalled. This launch's go, a TERM-ignoring one
    /// by KILL; an earlier launch's only when its pid and start both match a confirmed word.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_stop_takes_this_launch_and_only_the_confirmed_earlier_processes() {
        use std::os::unix::process::ExitStatusExt;

        struct Children(Vec<(&'static str, std::process::Child)>);
        impl Drop for Children {
            fn drop(&mut self) {
                for (_, child) in &mut self.0 {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let current = uuid::Uuid::new_v4().to_string();
        let earlier = uuid::Uuid::new_v4().to_string();
        let spawn = |argv: &[&str], marker: Option<&str>| {
            let mut command = std::process::Command::new(argv[0]);
            command.args(&argv[1..]).env_remove("AOE_SESSION_SOURCE");
            if let Some(marker) = marker {
                command.env("AOE_SESSION_SOURCE", marker);
            }
            command.spawn().unwrap()
        };
        let sleep = ["sleep", "600"];
        let mut children = Children(vec![
            ("current", spawn(&sleep, Some(&current))),
            (
                "ignores TERM",
                spawn(
                    &["sh", "-c", "trap '' TERM; exec sleep 600"],
                    Some(&current),
                ),
            ),
            ("earlier, confirmed", spawn(&sleep, Some(&earlier))),
            ("earlier, unconfirmed", spawn(&sleep, Some(&earlier))),
            ("earlier, pid reused", spawn(&sleep, Some(&earlier))),
            ("unmarked", spawn(&sleep, None)),
        ]);
        let pid = |index: usize| children.0[index].1.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read(format!("/proc/{}/cmdline", pid(1)))
            .unwrap()
            .starts_with(b"sleep")
        {
            assert!(std::time::Instant::now() < deadline, "the trap never ran");
            std::thread::sleep(Duration::from_millis(10));
        }
        let start = |pid: u32| -> u64 {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            let rest = stat.rsplit_once(") ").unwrap().1;
            rest.split_whitespace().nth(19).unwrap().parse().unwrap()
        };
        let root = tempfile::tempdir().unwrap();
        for index in 0..children.0.len() {
            std::os::unix::fs::symlink(
                format!("/proc/{}", pid(index)),
                root.path().join(pid(index).to_string()),
            )
            .unwrap();
        }
        let confirmed = format!("{}:{}", pid(2), start(pid(2)));
        let reused = format!("{}:{}", pid(4), start(pid(4)) + 1);

        let output = std::process::Command::new("/bin/sh")
            .args(["-c", STOP_SCRIPT, "sh", &current])
            .arg(root.path())
            .args([&confirmed, &reused])
            .env_remove("AOE_SESSION_SOURCE")
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "survived 0\n",
            "{output:?}"
        );
        let outcomes: Vec<_> = children
            .0
            .iter_mut()
            .map(|(name, child)| {
                let status = child.try_wait().unwrap();
                (*name, status.map(|status| status.signal()))
            })
            .collect();
        assert_eq!(
            outcomes,
            [
                ("current", Some(Some(15))),
                ("ignores TERM", Some(Some(9))),
                ("earlier, confirmed", Some(Some(15))),
                ("earlier, unconfirmed", None),
                ("earlier, pid reused", None),
                ("unmarked", None),
            ]
        );
    }

    /// The host side of the stop: confirmed processes go as `pid:start` words after the
    /// constant script, and only a reported count of zero is success.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_stop_succeeds_only_when_nothing_survives() {
        let bin = tempfile::tempdir().unwrap();
        for (name, tail, ok) in [
            ("stopped", "echo 'survived 0'", true),
            ("survivor", "echo 'survived 2'", false),
            ("silent", "true", false),
            ("fails", "echo 'survived 0'; exit 1", false),
        ] {
            let container = fake_container(bin.path(), name, tail);
            assert_eq!(
                stop(&container, "launch-2", &[(124, 1240)]).is_ok(),
                ok,
                "{name}"
            );
            let want = [
                "exec",
                "container-id",
                "/bin/sh",
                "-c",
                STOP_SCRIPT,
                "sh",
                "launch-2",
                "/proc",
                "124:1240",
            ];
            assert_eq!(recorded_argv(bin.path()), want, "{name}");
        }
    }

    /// Output the census can't trust is an error, never an empty container.
    #[test]
    fn a_listing_that_is_cut_off_or_garbled_is_an_error() {
        let line = |launch: &str| {
            let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
            let stat = format!("60 (claude) S 0 {} 9000 0 0", ["0"; 17].join(" "));
            format!("{launch} {} {}", b64(&stat), b64("claude\0"))
        };
        let whole = format!("up 100.0\n{}\nend\n", line("current"));
        assert_eq!(parse(&whole).unwrap().len(), 1);
        for broken in [
            String::new(),
            format!("up 100.0\n{}\n", line("current")),
            format!("{}\nend\n", line("current")),
            format!("up 100.0\n{}\nend\n", line("maybe")),
            "up 100.0\ncurrent !!! !!!\nend\n".to_owned(),
        ] {
            assert!(parse(&broken).is_err(), "{broken:?}");
        }
    }
}
