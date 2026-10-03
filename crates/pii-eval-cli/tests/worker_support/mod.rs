//! A synthetic worker world: the directories the custodian's sandbox would
//! mount (`stage`, `input`, `scratch`, a job file), built from the quickstart
//! synthetic population classed as protected, the inert fake scanner package
//! and a wrapper script standing in for the pinned Node runtime. Synthetic only.
//! Used by tests built with the feature `worker-test-adapters`.
#![cfg(feature = "worker-test-adapters")]
#![allow(dead_code)]

pub mod replica;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pii_eval_adapters::redact_secret::{PINNED_VERSION, shim_path_in_source_tree};
use pii_eval_adapters::sha256_of_tree;
use pii_eval_cli::exec::CancelToken;
use pii_eval_cli::status::Failure;
use pii_eval_cli::worker::bundle::{self, Member};
use pii_eval_cli::worker::contract::WorkerLayout;
use pii_eval_cli::worker::entry;
use pii_eval_cli::worker::launch::{WorkerOutput, WorkerRequest, run_worker_job};
use pii_eval_cli::worker::stage::SHIM_MEMBER;
use pii_eval_cli::worker::test_adapters;
use pii_eval_contracts::{
    CorpusSnapshot, RunClass, RunManifest, Sha256Digest, Visibility, parse_default, seal,
};
use serde_json::{Value, json};

use crate::cli_support::{fake_core_dir, limits, manifest_for, read_snapshot};
use crate::common::TempDir;

/// Text appended to the first variant of a population to make the inert fake
/// scanner misbehave (the fake is modified to react to it).
pub const CRASH: &str = " #CRASH";
/// Makes the fake block forever inside a scan call.
pub const HANG: &str = " #HANG";
/// Makes the fake print a line that is not a protocol message.
pub const GARBAGE: &str = " #GARBAGE";

/// Options of [`World::build`].
#[derive(Default, Clone)]
pub struct Opts {
    /// Misbehaviour trigger appended to the first variant text.
    pub trigger: Option<&'static str>,
    /// `resources.callTimeoutMs` of the configuration.
    pub call_timeout_ms: Option<u64>,
}

pub struct World {
    pub tmp: TempDir,
    pub stage: PathBuf,
    pub input: PathBuf,
    pub scratch: PathBuf,
    pub job: PathBuf,
    pub snapshot: CorpusSnapshot,
    pub manifest: RunManifest,
    pub package: PathBuf,
    pub node: PathBuf,
    pub entries: Vec<String>,
}

fn mode(path: &Path, m: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(m)).unwrap();
}

fn files_of(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_str().unwrap().to_owned();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

pub fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", Sha256Digest::of_bytes(bytes).as_str())
}

impl World {
    pub fn build(label: &str, node: &Path, opts: &Opts) -> World {
        let tmp = TempDir::new(label);
        let root = &tmp.0;
        let (stage, input, scratch) =
            (root.join("stage"), root.join("input"), root.join("scratch"));
        for d in [&stage, &input, &scratch] {
            std::fs::create_dir_all(d).unwrap();
        }
        // The scanner package: the inert fake, optionally taught to misbehave.
        let package = root.join("package-src");
        crate::cli_support::copy_dir(&fake_core_dir(), &package);
        if opts.trigger.is_some() {
            let index = package.join("lib/index.js");
            let text = std::fs::read_to_string(&index).unwrap();
            let marker = "export const scan = (text, options) => {";
            assert!(text.contains(marker));
            let prelude = format!(
                "{marker}\n  if (text.includes('#CRASH')) process.exit(3);\n  if (text.includes('#HANG')) {{ for (;;) {{}} }}\n  if (text.includes('#GARBAGE')) process.stdout.write('{{\"type\":\\n');"
            );
            std::fs::write(&index, text.replace(marker, &prelude)).unwrap();
        }
        // The population, classed as protected.
        let mut snapshot: CorpusSnapshot =
            read_snapshot(&crate::cli_support::example_dir().join("snapshot.json"));
        snapshot.semantic.population.visibility = Visibility::Protected;
        // The launcher assembles at the current schema version (part of the digest).
        snapshot.schema_version = pii_eval_contracts::SchemaVersion::CURRENT;
        if let Some(t) = opts.trigger {
            let v = &mut snapshot.semantic.cases[0].variants[0];
            v.text.push_str(t);
            v.text_digest = Sha256Digest::of_bytes(v.text.as_bytes());
        }
        seal(&mut snapshot).unwrap();
        let mut manifest: RunManifest = manifest_for(&snapshot, &package, node, limits(2, 1), 2);
        manifest.semantic.run_class = RunClass::Protected;
        manifest.semantic.population.visibility = Visibility::Protected;
        manifest.semantic.population.population_digest = snapshot.semantic_digest.clone();
        seal(&mut manifest).unwrap();

        // Entries: one authored case each.
        let mut entries = Vec::new();
        for case in &snapshot.semantic.cases {
            let name = case.case_id.as_str().to_owned();
            let path = input.join(&name);
            std::fs::write(&path, entry::encode(case).unwrap()).unwrap();
            mode(&path, 0o400);
            entries.push(name);
        }
        entries.sort();
        // Staged artifacts.
        let shim = std::fs::read(shim_path_in_source_tree()).unwrap();
        let adapter_bundle = bundle::encode(&[Member {
            path: SHIM_MEMBER.into(),
            bytes: shim,
            executable: false,
        }])
        .unwrap();
        let members: Vec<Member> = files_of(&package)
            .into_iter()
            .map(|(path, bytes)| Member {
                path,
                bytes,
                executable: false,
            })
            .collect();
        let candidate_bundle = bundle::encode(&members).unwrap();
        let tree = sha256_of_tree(&std::fs::canonicalize(&package).unwrap()).unwrap();
        let engine = b"synthetic engine stand-in\n".to_vec();
        let runtime = format!("#!/bin/sh\nexec \"{}\" \"$@\"\n", node.display()).into_bytes();
        let put = |name: &str, bytes: &[u8], m: u32| {
            let p = stage.join(name);
            std::fs::write(&p, bytes).unwrap();
            mode(&p, m);
        };
        put("engine", &engine, 0o500);
        put("adapter", &adapter_bundle, 0o500);
        put("candidate", &candidate_bundle, 0o500);
        put("scanner-0", &runtime, 0o500);
        let mut resources = json!({"maxWorkers": 2});
        if let Some(ms) = opts.call_timeout_ms {
            resources["callTimeoutMs"] = json!(ms);
        }
        let config = json!({
            "schema": "pii-eval-worker-config/1",
            "protocol": {"name": "pii-v1", "version": "2"},
            "runClass": "protected",
            "population": {"digest": snapshot.semantic_digest.as_str()},
            "snapshot": {
                "population": serde_json::to_value(&snapshot.semantic.population).unwrap(),
                "generation": serde_json::to_value(&snapshot.semantic.generation).unwrap(),
            },
            "manifest": serde_json::to_value(&manifest).unwrap(),
            "product": "candidate",
            "artifacts": {
                "engine": {"sha256": sha(&engine)},
                "adapter": {"bundleDigest": sha(&adapter_bundle)},
                "candidate": {
                    "bundleDigest": sha(&candidate_bundle),
                    "treeDigest": tree.as_str(),
                    "entry": "lib/index.js",
                    "version": PINNED_VERSION,
                },
                "runtime": {"sha256": sha(&runtime)},
            },
            "resources": resources,
        });
        put("config", config.to_string().as_bytes(), 0o400);
        let job = root.join("job.json");
        let job_doc = job_json(&entries);
        std::fs::write(&job, job_doc).unwrap();
        mode(&job, 0o400);
        World {
            tmp,
            stage,
            input,
            scratch,
            job,
            snapshot,
            manifest,
            package,
            node: node.to_path_buf(),
            entries,
        }
    }

    pub fn layout(&self) -> WorkerLayout {
        WorkerLayout {
            stage: self.stage.clone(),
            input: self.input.clone(),
            scratch: self.scratch.clone(),
        }
    }

    /// Run the launcher in this process with the test adapters.
    pub fn run(&self, cancel: &CancelToken) -> Result<WorkerOutput, Failure> {
        // The sandbox's scratch is fresh for every run; a test reuses one world.
        let _ = std::fs::remove_dir_all(self.scratch.join("pii-eval-worker"));
        let _ = std::fs::remove_file(self.scratch.join(test_adapters::CHANNEL_FILE));
        let adapters = test_adapters::adapters(self.layout());
        run_worker_job(
            &WorkerRequest {
                job: &self.job,
                adapters: &adapters,
                policy: test_adapters::POLICY,
            },
            cancel,
        )
    }

    pub fn run_ok(&self) -> WorkerOutput {
        match self.run(&CancelToken::new()) {
            Ok(o) => o,
            Err(f) => panic!("the launch was refused: {}", f.human()),
        }
    }

    pub fn refusal(&self) -> Failure {
        match self.run(&CancelToken::new()) {
            Ok(_) => panic!("the launch must be refused"),
            Err(f) => f,
        }
    }

    pub fn stage_bytes(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.stage.join(name)).unwrap()
    }

    pub fn stage_put(&self, name: &str, bytes: &[u8], m: u32) {
        let p = self.stage.join(name);
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, bytes).unwrap();
        mode(&p, m);
    }

    /// Edit the staged configuration as JSON.
    pub fn edit_config(&self, edit: impl FnOnce(&mut Value)) {
        let mut v: Value = serde_json::from_slice(&self.stage_bytes("config")).unwrap();
        edit(&mut v);
        self.stage_put("config", v.to_string().as_bytes(), 0o400);
    }

    /// Replace the job document.
    pub fn set_job(&self, text: &str) {
        let _ = std::fs::remove_file(&self.job);
        std::fs::write(&self.job, text).unwrap();
        mode(&self.job, 0o400);
    }

    /// Pins of the staged files, as the custodian's plan would freeze them.
    pub fn pins(&self) -> Vec<(String, String)> {
        ["engine", "adapter", "candidate", "config", "scanner-0"]
            .iter()
            .map(|n| ((*n).to_owned(), sha(&self.stage_bytes(n))))
            .collect()
    }
}

/// The job document exactly as the custodian's `job_document` serializes it.
pub fn job_json(entries: &[String]) -> String {
    serde_json::to_string(&json!({
        "schema": "private-custodian.worker-job/1",
        "domain": "pii",
        "protocol": {"name": "pii-v1", "version": "2"},
        "roster": entries.len(),
        "entries": entries,
    }))
    .unwrap()
}

pub fn parse_snapshot(bytes: &[u8]) -> CorpusSnapshot {
    parse_default(bytes).unwrap()
}
