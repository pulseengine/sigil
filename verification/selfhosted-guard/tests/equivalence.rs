//! Equivalence gate for the Rust port: run the old `check.py` and this binary
//! on the same inputs and require identical stdout and exit code.
//!
//! Inputs: every case of the embedded decision table (21), extra shapes the
//! table does not cover, the `--self-test` report itself, and the live
//! `.github/workflows` tree of this repository. Fails closed: if python3 or
//! PyYAML is missing the test fails, it does not skip.

use selfhosted_guard::cases::{self, GOOD};
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn python_check() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("check.py")
}

/// (stdout, exit code) of one command.
fn outcome(cmd: &mut Command) -> (String, i32) {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("cannot run {cmd:?}: {e}"));
    (
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
        out.status.code().expect("exit code"),
    )
}

fn python(arg: &Path) -> (String, i32) {
    outcome(Command::new("python3").arg(python_check()).arg(arg))
}

fn rust(arg: &Path) -> (String, i32) {
    outcome(Command::new(env!("CARGO_BIN_EXE_selfhosted-guard")).arg(arg))
}

fn require_python() {
    let ok = Command::new("python3")
        .args(["-c", "import yaml"])
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        ok,
        "the equivalence gate needs python3 with PyYAML (the old check.py is the oracle); it does not skip"
    );
}

/// Write `files` under <tmp>/.github/workflows and compare both checkers on it.
fn assert_equivalent(label: &str, files: &[(&str, &str)]) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let wf = tmp.path().join(".github/workflows");
    std::fs::create_dir_all(&wf).expect("mkdir");
    for (name, text) in files {
        std::fs::write(wf.join(name), text).expect("write workflow");
    }
    let (py, rs) = (python(tmp.path()), rust(tmp.path()));
    assert_eq!(rs, py, "{label}: Rust (left) and check.py (right) disagree");
}

#[test]
fn every_decision_table_case_is_equivalent() {
    require_python();
    let all = cases::cases();
    assert_eq!(all.len(), 21, "check.py's self-test has 21 cases");
    for case in &all {
        let text = case.workflow();
        assert_equivalent(case.name, &[("w.yml", &text)]);
    }
}

#[test]
fn self_test_report_is_equivalent() {
    require_python();
    let py = outcome(
        Command::new("python3")
            .arg(python_check())
            .arg("--self-test"),
    );
    let rs = outcome(Command::new(env!("CARGO_BIN_EXE_selfhosted-guard")).arg("--self-test"));
    assert_eq!(rs, py);
    assert_eq!(rs.1, 0, "{}", rs.0);
}

#[test]
fn live_workflow_tree_is_equivalent() {
    require_python();
    let root = repo_root();
    let (py, rs) = (python(&root), rust(&root));
    assert_eq!(
        rs, py,
        "live .github/workflows: Rust (left) and check.py (right) disagree"
    );
    assert_eq!(rs.1, 0, "{}", rs.0);
    assert!(
        rs.0.contains("on self-hosted behind the fail-closed form"),
        "compared nothing: {}",
        rs.0
    );
}

/// Shapes beyond the decision table: trigger spellings, file ordering and
/// extensions, reusable-workflow calls, missing or null runs-on, quoting.
#[test]
fn extra_shapes_are_equivalent() {
    require_python();
    let good = format!("  g:\n    runs-on: {GOOD}\n    steps: []\n");
    let wf =
        |on: &str, job: &str| format!("on: {on}\njobs:\n{good}  j:\n    {job}\n    steps: []\n");
    let shapes: Vec<(&str, String)> = vec![
        ("on as a scalar", wf("push", "runs-on: ubuntu-latest")),
        (
            "on as a list with an untrusted trigger",
            wf(
                "[push, pull_request_target, issue_comment]",
                "runs-on: ubuntu-latest",
            ),
        ),
        (
            "on as a flow mapping",
            wf(
                "{push: {branches: [main]}, workflow_run: {}}",
                "runs-on: ubuntu-latest",
            ),
        ),
        (
            "quoted on key",
            format!("\"on\": [push, workflow_call]\njobs:\n{good}"),
        ),
        (
            "true as the trigger key",
            format!("true: [push, workflow_call]\njobs:\n{good}"),
        ),
        ("runs-on missing", wf("push", "name: no runner")),
        ("runs-on null", wf("push", "runs-on:")),
        ("runs-on an integer", wf("push", "runs-on: 42")),
        ("runs-on a float", wf("push", "runs-on: 3.10")),
        (
            "runs-on with quotes inside",
            wf("push", "runs-on: \"it's a 'label'\""),
        ),
        (
            "runs-on with both quote kinds",
            wf("push", "runs-on: 'a \"b\" c''s'"),
        ),
        (
            "runs-on with surrounding whitespace",
            wf("push", "runs-on: \"  ubuntu-24.04  \""),
        ),
        (
            "hosted image with a trailing newline",
            wf("push", "runs-on: \"ubuntu-24.04\\n\""),
        ),
        (
            "runs-on a non-ASCII label",
            wf("push", "runs-on: \"läbel\u{a0}x\""),
        ),
        (
            "runner group as a flow mapping",
            wf("push", "runs-on: {group: big, labels: [x, y]}"),
        ),
        (
            "matrix key missing",
            wf(
                "push",
                "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        python: ['3.12']",
            ),
        ),
        (
            "matrix value not a string",
            wf(
                "push",
                "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest, 3]",
            ),
        ),
        (
            "matrix include only",
            wf(
                "push",
                "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        include:\n          - os: macos-14\n          - os: ubuntu-24.04",
            ),
        ),
        (
            "matrix include as a mapping",
            wf(
                "push",
                "runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n        include: {os: light}",
            ),
        ),
        (
            "matrix ref with odd spacing",
            wf(
                "push",
                "runs-on: ${{matrix.os   }}\n    strategy:\n      matrix:\n        os: [ubuntu-latest]",
            ),
        ),
        (
            "strategy null",
            wf("push", "runs-on: ${{ matrix.os }}\n    strategy:"),
        ),
        (
            "reusable-workflow call is skipped",
            wf("push", "uses: ./.github/workflows/x.yml"),
        ),
        (
            "reusable call that also sets runs-on",
            wf(
                "push",
                "uses: ./.github/workflows/x.yml\n    runs-on: light",
            ),
        ),
        (
            "fallback pinned to a three-part version",
            wf(
                "push",
                &format!(
                    "runs-on: {}",
                    GOOD.replace("ubuntu-latest", "ubuntu-24.04.1")
                ),
            ),
        ),
        (
            "anchors and aliases",
            format!(
                "on: [push]\nx: &img ubuntu-24.04\njobs:\n{good}  j:\n    runs-on: *img\n    steps: []\n"
            ),
        ),
        ("no jobs", "on: push\n".to_owned()),
        ("empty file", String::new()),
    ];
    for (label, text) in &shapes {
        assert_equivalent(label, &[("w.yml", text)]);
    }
    // Ordering and discovery: several files, both extensions, one ignored.
    assert_equivalent(
        "several files",
        &[
            ("b.yaml", &wf("push", "runs-on: light")),
            (
                "a.yml",
                &wf("[push, workflow_call]", "runs-on: ubuntu-latest"),
            ),
            ("C.yml", &wf("push", "runs-on: [self-hosted]")),
            ("notes.txt", "runs-on: light\n"),
            (".hidden.yml", &wf("push", "runs-on: ubuntu-latest")),
        ],
    );
    // No workflows at all.
    assert_equivalent("no workflow files", &[]);
}
