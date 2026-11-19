//! The decision table `check.py --self-test` embeds, in the same order with
//! the same names, so `--self-test` output is comparable line for line.

pub const GOOD: &str = concat!(
    "${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name",
    " == github.repository) && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"light\"]') || 'ubuntu-latest' }}"
);
pub const FAIL_OPEN: &str = concat!(
    "${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || ",
    "fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"light\"]') }}"
);

pub struct Case {
    pub name: &'static str,
    /// The block under `on:`.
    pub trigger: &'static str,
    /// The job body line(s) that set runs-on (and strategy).
    pub job: String,
    /// The exit code check.py gives.
    pub want: i32,
}

impl Case {
    /// The workflow file check.py's self-test writes for this case. Every case
    /// but "only hosted" also carries one good guarded job, so a bad case
    /// cannot pass merely by "compared nothing".
    pub fn workflow(&self) -> String {
        let guard = if self.name.starts_with("only hosted") {
            String::new()
        } else {
            format!("  g:\n    runs-on: {GOOD}\n    steps: []\n")
        };
        format!(
            "on:\n  {}\njobs:\n{guard}  j:\n    {}\n    steps: []\n",
            self.trigger, self.job
        )
    }
}

pub fn cases() -> Vec<Case> {
    let pinned = GOOD.replace("'ubuntu-latest'", "'ubuntu-24.04'");
    let label_fallback = GOOD.replace("'ubuntu-latest'", "'light'");
    let c = |name, trigger, job: &str, want| Case {
        name,
        trigger,
        job: job.to_owned(),
        want,
    };
    vec![
        c(
            "fail-closed form on pull_request passes",
            "pull_request:",
            &format!("runs-on: {GOOD}"),
            0,
        ),
        c(
            "fail-closed form with a pinned hosted fallback passes",
            "pull_request:",
            &format!("runs-on: {pinned}"),
            0,
        ),
        c(
            "fail-closed form falling back to a label fails",
            "pull_request:",
            &format!("runs-on: {label_fallback}"),
            1,
        ),
        c(
            "hosted image passes",
            "pull_request:",
            "runs-on: ubuntu-24.04",
            0,
        ),
        c(
            "matrix of hosted images passes",
            "pull_request:",
            "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, macos-latest]\n        include:\n          - os: windows-latest",
            0,
        ),
        c(
            "plain self-hosted list fails",
            "pull_request:",
            "runs-on: [self-hosted, linux, x64, light]",
            1,
        ),
        c(
            "bare label without the word self-hosted fails",
            "pull_request:",
            "runs-on: light",
            1,
        ),
        c(
            "label list without the word self-hosted fails",
            "pull_request:",
            "runs-on: [linux, light]",
            1,
        ),
        c(
            "runner group fails",
            "pull_request:",
            "runs-on:\n      group: hetzner-private",
            1,
        ),
        c(
            "fail-open .fork form fails",
            "pull_request:",
            &format!("runs-on: {FAIL_OPEN}"),
            1,
        ),
        c(
            "matrix with a self-hosted label fails",
            "pull_request:",
            "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, light]",
            1,
        ),
        c(
            "matrix include with a label fails",
            "pull_request:",
            "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include:\n          - os: lean-mem",
            1,
        ),
        c(
            "matrix include as a mapping fails",
            "pull_request:",
            "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include: {os: light}",
            1,
        ),
        c(
            "matrix include from an expression fails",
            "pull_request:",
            "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include: ${{ fromJSON(needs.a.outputs.inc) }}",
            1,
        ),
        c(
            "matrix from an expression fails",
            "pull_request:",
            "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix: ${{ fromJSON(needs.a.outputs.m) }}",
            1,
        ),
        c(
            "runner from needs output fails",
            "pull_request:",
            "runs-on: ${{ needs.a.outputs.runner }}",
            1,
        ),
        c(
            "runner from vars fails",
            "pull_request:",
            "runs-on: ${{ vars.RUNNER }}",
            1,
        ),
        c(
            "good form under pull_request_target fails",
            "pull_request_target:",
            &format!("runs-on: {GOOD}"),
            1,
        ),
        c(
            "good form under workflow_run fails",
            "workflow_run:\n    workflows: [CI]",
            &format!("runs-on: {GOOD}"),
            1,
        ),
        c(
            "good form under workflow_call fails",
            "workflow_call:",
            &format!("runs-on: {GOOD}"),
            1,
        ),
        c(
            "only hosted jobs fails (compared nothing)",
            "pull_request:",
            "runs-on: ubuntu-latest",
            1,
        ),
    ]
}
