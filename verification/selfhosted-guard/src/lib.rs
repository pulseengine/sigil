//! No fork PR reaches a self-hosted runner.
//!
//! Rust port of `check.py` in this directory (adapted from pulseengine/ordeal
//! `scripts/check_selfhosted_fork_guard.py`, ordeal#322). GitHub routes a job
//! by labels, so `runs-on: light`, `[linux, light]` or `{group: X}` reach the
//! self-hosted pool without the word `self-hosted`. The check therefore
//! allowlists runs-on instead of hunting for a word. Each job's runs-on must
//! be one of:
//!
//!   - a GitHub-hosted image string: ubuntu-*, macos-*, windows-*;
//!   - exactly the fail-closed form
//!     `${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && fromJSON('[...]') || 'ubuntu-24.04' }}`
//!     (the fallback is a hosted Ubuntu image: ubuntu-latest or a pinned
//!     ubuntu-NN.NN), in a workflow whose triggers are all in [`TRUSTED`];
//!   - `${{ matrix.KEY }}` where every literal value of KEY (list and include
//!     entries) is a hosted image.
//!
//! Anything else fails. It also fails when no job uses the fail-closed form,
//! so a pass always compared something.
//!
//! The output is byte-identical to `check.py` (including Python `repr`
//! formatting in rejection reasons, which external controls match on); the
//! equivalence test in `tests/equivalence.rs` runs both and compares. Known
//! divergence, in rejection *text* only, never in the verdict: PyYAML reads
//! YAML 1.1 and this reads YAML 1.2, so a plain scalar such as `yes`, `017`
//! or `2001-12-14` prints as a string here and as a bool / octal int / date
//! there. A hosted-image or fail-closed-form string resolves to a string in
//! both schemas, so the verdict should not flip; that is argued, not
//! exhaustively tested.

use regex::Regex;
use std::sync::LazyLock;
use yaml_rust2::{Yaml, YamlLoader};

pub mod cases;

static FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^\$\{\{ \(github\.event_name != 'pull_request' \|\| ",
        r"github\.event\.pull_request\.head\.repo\.full_name == github\.repository\) && ",
        r#"fromJSON\('\[[^\]]*"self-hosted"[^\]]*\]'\) \|\| 'ubuntu-(?:latest|[0-9]+\.[0-9]+)' \}\}\n?\z"#,
    ))
    .expect("FORM regex")
});
// Python's `$` (no MULTILINE) also matches before one final newline: `\n?\z`.
static HOSTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(ubuntu|macos|windows)-[A-Za-z0-9._-]+\n?\z").expect("HOSTED regex")
});
// Python's `\s` on str also matches U+001C..U+001F, which Unicode White_Space does not.
static MATRIX_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\$\{\{[\s\x1c-\x1f]*matrix\.([A-Za-z0-9_-]+)[\s\x1c-\x1f]*\}\}\n?\z")
        .expect("MATRIX_REF regex")
});

/// Triggers only a maintainer or this repository's own branches can cause,
/// plus pull_request, which the expression itself sends to a hosted runner
/// unless the head repository is this one. `release` (sigil addition, for
/// wasm-signing.yml): only maintainers publish releases. workflow_call is NOT
/// trusted: a called workflow inherits its caller's event, which could be a
/// fork-PR context.
pub const TRUSTED: &[&str] = &[
    "push",
    "pull_request",
    "schedule",
    "workflow_dispatch",
    "merge_group",
    "release",
];

/// The result of one run: what it printed and its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub stdout: String,
    pub code: i32,
}

/// Where `check.py` would raise (and print nothing to stdout): an unparsable
/// or unexpectedly shaped workflow. Exit code 1, message to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash(pub String);

fn crash<T>(msg: impl Into<String>) -> Result<T, Crash> {
    Err(Crash(msg.into()))
}

// ── Python value semantics over YAML nodes ────────────────────────────────

fn truthy(v: &Yaml) -> bool {
    match v {
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => false,
        Yaml::Boolean(b) => *b,
        Yaml::Integer(i) => *i != 0,
        Yaml::Real(_) => v.as_f64().is_some_and(|f| f != 0.0),
        Yaml::String(s) => !s.is_empty(),
        Yaml::Array(a) => !a.is_empty(),
        Yaml::Hash(h) => !h.is_empty(),
    }
}

/// `str.strip()`: Python's `str.isspace` set is Unicode White_Space plus U+001C..U+001F.
fn py_strip(s: &str) -> &str {
    let ws = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    s.trim_matches(ws)
}

fn py_printable(c: char) -> bool {
    let u = c as u32;
    if u < 0x20 || u == 0x7f || (0x80..=0xa0).contains(&u) || u == 0xad {
        return false;
    }
    !matches!(u,
        0x1680 | 0x2000..=0x200f | 0x2028..=0x202f | 0x205f..=0x2064 | 0x3000
        | 0xd800..=0xf8ff | 0xfeff | 0xfff9..=0xfffb | 0xe0001 | 0xe0020..=0xe007f
        | 0xf0000..=0x10ffff)
}

fn py_repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if py_printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

/// `repr(float)`: shortest round-trip digits, scientific outside 1e-4 <= |x| < 1e16.
fn py_repr_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let sci = format!("{f:e}");
    let (mant, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let exp: i32 = exp.parse().expect("exponent is an integer");
    if f != 0.0 && !(-4..16).contains(&exp) {
        let sign = if exp < 0 { '-' } else { '+' };
        return format!("{mant}e{sign}{:02}", exp.abs());
    }
    let s = format!("{f}");
    if s.contains('.') { s } else { format!("{s}.0") }
}

/// `repr()` of a YAML-loaded value.
fn py_repr(v: &Yaml) -> String {
    match v {
        Yaml::String(s) => py_repr_str(s),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Real(_) => v.as_f64().map_or_else(|| "None".into(), py_repr_float),
        Yaml::Boolean(true) => "True".into(),
        Yaml::Boolean(false) => "False".into(),
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => "None".into(),
        Yaml::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Yaml::Hash(h) => format!(
            "{{{}}}",
            h.iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// `str()` of a YAML-loaded value: like `repr` except a string is itself.
fn py_str(v: &Yaml) -> String {
    match v {
        Yaml::String(s) => s.clone(),
        _ => py_repr(v),
    }
}

fn get<'a>(h: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    h.get(&Yaml::String(key.to_owned()))
}

/// `"key" in spec` for whatever type spec is (dict key, list element, substring).
fn py_contains(container: &Yaml, key: &str) -> Result<bool, Crash> {
    match container {
        Yaml::Hash(h) => Ok(get(h, key).is_some()),
        Yaml::Array(a) => Ok(a.iter().any(|e| matches!(e, Yaml::String(s) if s == key))),
        Yaml::String(s) => Ok(s.contains(key)),
        other => crash(format!(
            "argument of type '{}' is not iterable",
            type_name(other)
        )),
    }
}

fn type_name(v: &Yaml) -> &'static str {
    match v {
        Yaml::String(_) => "str",
        Yaml::Integer(_) => "int",
        Yaml::Real(_) => "float",
        Yaml::Boolean(_) => "bool",
        Yaml::Array(_) => "list",
        Yaml::Hash(_) => "dict",
        _ => "NoneType",
    }
}

/// `doc.get(True, doc.get("on"))`: PyYAML (YAML 1.1) loads a plain `on:` key
/// as the boolean True, so do the same with every spelling it resolves to True.
fn triggers(doc: &yaml_rust2::yaml::Hash) -> Option<&Yaml> {
    const TRUE_WORDS: &[&str] = &["on", "On", "ON", "yes", "Yes", "YES"];
    doc.iter()
        .filter(|(k, _)| match k {
            Yaml::Boolean(true) => true,
            Yaml::String(s) => TRUE_WORDS.contains(&s.as_str()),
            _ => false,
        })
        .map(|(_, v)| v)
        .next_back()
}

/// Literal values of matrix.KEY, or None if any is not a plain string.
fn matrix_values(spec: &yaml_rust2::yaml::Hash, key: &str) -> Result<Option<Vec<Yaml>>, Crash> {
    let strategy = match get(spec, "strategy") {
        Some(s) if truthy(s) => s,
        _ => return Ok(None), // `{}.get("matrix")` is None
    };
    let Yaml::Hash(strategy) = strategy else {
        return crash(format!(
            "'{}' object has no attribute 'get'",
            type_name(strategy)
        ));
    };
    let Some(Yaml::Hash(m)) = get(strategy, "matrix") else {
        return Ok(None);
    };
    let mut vals = Vec::new();
    if let Some(v) = get(m, key) {
        let Yaml::Array(list) = v else {
            return Ok(None);
        };
        vals.extend(list.iter().cloned());
    }
    // include must be a list of mappings. Anything else (a mapping, or an
    // expression string that computes it) cannot be read statically, so fail
    // closed: found by plant's corpus run (s18) on 2026-11-18.
    if let Some(inc) = get(m, "include").filter(|i| truthy(i)) {
        let Yaml::Array(items) = inc else {
            return Ok(None);
        };
        if !items.iter().all(|i| matches!(i, Yaml::Hash(_))) {
            return Ok(None);
        }
        for item in items {
            if let Yaml::Hash(ih) = item
                && let Some(v) = get(ih, key)
            {
                vals.push(v.clone());
            }
        }
    }
    if vals.is_empty() || !vals.iter().all(|v| matches!(v, Yaml::String(_))) {
        return Ok(None);
    }
    Ok(Some(vals))
}

/// The per-job verdicts: every checked job in order, the rejected ones with
/// their reason, and how many use the fail-closed form.
pub struct Report {
    pub jobs: Vec<String>,
    pub bad: Vec<(String, String)>,
    pub guarded: usize,
}

/// Check workflow files given as (file name, contents). Files are visited in
/// sorted name order, as `check.py` does.
pub fn check(files: &[(String, String)]) -> Result<Report, Crash> {
    let mut files: Vec<&(String, String)> = files.iter().collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let (mut jobs, mut bad, mut guarded) = (Vec::new(), Vec::new(), 0usize);
    for (name, text) in files {
        let docs = YamlLoader::load_from_str(text).or_else(|e| crash(format!("{name}: {e}")))?;
        if docs.len() > 1 {
            return crash(format!("{name}: expected a single document in the stream"));
        }
        let empty = Yaml::Hash(Default::default());
        let doc = match docs.first() {
            Some(d) if truthy(d) => d,
            _ => &empty,
        };
        let Yaml::Hash(doc) = doc else {
            return crash(format!(
                "{name}: '{}' object has no attribute 'get'",
                type_name(doc)
            ));
        };
        let mut events: Vec<String> = match triggers(doc).or_else(|| get(doc, "on")) {
            Some(on) if truthy(on) => match on {
                Yaml::Hash(h) => h.keys().map(py_str).collect(),
                Yaml::Array(a) => {
                    if let Some(u) = a
                        .iter()
                        .find(|e| matches!(e, Yaml::Array(_) | Yaml::Hash(_)))
                    {
                        return crash(format!("{name}: unhashable type: '{}'", type_name(u)));
                    }
                    a.iter().map(py_str).collect()
                }
                other => vec![py_str(other)],
            },
            _ => Vec::new(),
        };
        events.sort();
        events.dedup();
        let jobs_node = match get(doc, "jobs") {
            Some(j) if truthy(j) => j,
            _ => continue,
        };
        let Yaml::Hash(job_map) = jobs_node else {
            return crash(format!(
                "{name}: '{}' object has no attribute 'items'",
                type_name(jobs_node)
            ));
        };
        for (job, spec) in job_map {
            if py_contains(spec, "uses")? && !py_contains(spec, "runs-on")? {
                continue; // reusable-workflow call: the callee's jobs are checked in its own file
            }
            let Yaml::Hash(spec) = spec else {
                return crash(format!(
                    "{name}: '{}' object has no attribute 'get'",
                    type_name(spec)
                ));
            };
            let where_ = format!("{name}:{}", py_str(job));
            jobs.push(where_.clone());
            let ro = get(spec, "runs-on");
            let text = match ro {
                Some(Yaml::String(s)) => Some(py_strip(s)),
                _ => None,
            };
            if text.is_some_and(|t| HOSTED.is_match(t)) {
                continue;
            }
            if text.is_some_and(|t| FORM.is_match(t)) {
                guarded += 1;
                let untrusted: Vec<&str> = events
                    .iter()
                    .map(String::as_str)
                    .filter(|e| !TRUSTED.contains(e))
                    .collect();
                if !untrusted.is_empty() {
                    bad.push((
                        where_,
                        format!(
                            "self-hosted under trigger(s) outside the allowlist: {}",
                            untrusted.join(", ")
                        ),
                    ));
                }
                continue;
            }
            if let Some(caps) = text.and_then(|t| MATRIX_REF.captures(t)) {
                let key = &caps[1];
                let vals = matrix_values(spec, key)?;
                if let Some(v) = &vals
                    && v.iter()
                        .all(|s| matches!(s, Yaml::String(s) if HOSTED.is_match(s)))
                {
                    continue;
                }
                let shown = vals.map_or_else(|| "None".to_owned(), |v| py_repr(&Yaml::Array(v)));
                bad.push((
                    where_,
                    format!("matrix.{key} has a value that is not a hosted image: {shown}"),
                ));
                continue;
            }
            let shown = ro.map_or_else(|| "None".to_owned(), py_repr);
            bad.push((
                where_,
                format!("runs-on {shown} is neither a hosted image nor the fail-closed form"),
            ));
        }
    }
    Ok(Report { jobs, bad, guarded })
}

/// `run()` of check.py over in-memory files: the report lines and exit code.
pub fn run(files: &[(String, String)]) -> Result<Outcome, Crash> {
    let Report { jobs, bad, guarded } = check(files)?;
    let mut out = String::new();
    for w in &jobs {
        match bad.iter().find(|(b, _)| b == w) {
            Some((_, why)) => out.push_str(&format!("FAIL  {w}: {why}\n")),
            None => out.push_str(&format!("ok    {w}\n")),
        }
    }
    let code = if guarded == 0 {
        out.push_str("FAIL  no job uses the fail-closed form: this check compared nothing\n");
        1
    } else if !bad.is_empty() {
        out.push_str(&format!(
            "FAIL  {} job(s) a fork PR could route to a self-hosted runner\n",
            bad.len()
        ));
        1
    } else {
        out.push_str(&format!(
            "{} job(s) ok, {guarded} on self-hosted behind the fail-closed form\n",
            jobs.len()
        ));
        0
    };
    Ok(Outcome { stdout: out, code })
}

/// Read `<root>/.github/workflows/{*.yml,*.yaml}` the way pathlib's glob does
/// (case-sensitive, dotfiles included; a missing directory is no files).
pub fn read_workflows(root: &std::path::Path) -> Result<Vec<(String, String)>, Crash> {
    let dir = root.join(".github").join("workflows");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.or_else(|e| crash(format!("{}: {e}", dir.display())))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
            continue;
        }
        let text =
            std::fs::read_to_string(entry.path()).or_else(|e| crash(format!("{name}: {e}")))?;
        files.push((name, text));
    }
    Ok(files)
}

/// The embedded decision table, run over in-memory files.
pub fn self_test() -> Outcome {
    let mut out = String::new();
    let mut failed = false;
    for case in cases::cases() {
        let got = run(&[("w.yml".to_owned(), case.workflow())]).map_or(1, |o| o.code);
        let ok = got == case.want;
        out.push_str(&format!(
            "{}  {}\n",
            if ok { "ok  " } else { "FAIL" },
            case.name
        ));
        failed |= !ok;
    }
    out.push_str(if failed {
        "SELF-TEST FAILED\n"
    } else {
        "self-test ok\n"
    });
    Outcome {
        stdout: out,
        code: i32::from(failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr_str("light"), "'light'");
        assert_eq!(py_repr_str("it's"), "\"it's\"");
        assert_eq!(py_repr_str("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(py_repr_str("tab\there\n"), "'tab\\there\\n'");
        assert_eq!(py_repr_str("\u{7}\u{a0}é"), "'\\x07\\xa0é'");
        assert_eq!(py_repr_float(3.1), "3.1");
        assert_eq!(py_repr_float(3.0), "3.0");
        assert_eq!(py_repr_float(1e16), "1e+16");
        assert_eq!(py_repr_float(1.5e-5), "1.5e-05");
        assert_eq!(py_repr_float(0.0001), "0.0001");
    }

    #[test]
    fn self_test_passes() {
        let o = self_test();
        assert_eq!(o.code, 0, "{}", o.stdout);
    }
}
