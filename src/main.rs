use serde::Serialize;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

#[derive(Serialize, Default)]
struct FileInfo {
    pub error: Option<String>,
    pub name: String,
    pub size: usize,
    pub format: String,
    pub bintype: String,
    pub compiler: Vec<String>,
    pub lang: String,
    pub machine: String,
    pub os: String,
    pub strings: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub sections: Vec<BlockInfo>,
    pub segments: Vec<BlockInfo>,
    pub links: Vec<String>,
    pub zignatures: Vec<Zignature>,
    pub dumpinfo: String,
    pub yara: String,
}

#[derive(Serialize)]
struct ImportInfo {
    pub lib: String,
    pub name: String,
}

#[derive(Serialize)]
struct BlockInfo {
    pub name: String,
    pub size: usize,
    pub ssdeep: String,
    pub entropy: f32,
}

#[derive(Serialize)]
struct Zignature {
    pub name: String,
    pub bytes: Vec<u8>,
    pub mask: String,
    pub bbsum: usize,
    pub addr: usize,
    pub n_vars: usize,
    pub entropy: f32,
}

fn process_file(path: String, yara_rules_file: String) -> String {
    let mut result = FileInfo::default();
    result.name = path.split('/').last().unwrap().to_string();
    result.yara = yara(path, yara_rules_file);
    serde_json::to_string(&result).expect("serialization failure")
}

pub fn yara(path: String, yara_rules_file: String) -> String {
    let err = "yara processing error".to_string();
    match Command::new("yara")
        .arg("-f")
        .arg("-w")
        .arg(&yara_rules_file)
        .arg(&path)
        .output()
    {
        Ok(result) => String::from_utf8(result.stdout).unwrap_or(err),
        _ => err,
    }
}

fn spawn_worker(
    id: usize,
    in_queue: Receiver<String>,
    notify: Sender<usize>,
) -> thread::JoinHandle<()> {
    let timeout = env::var("WORKER_TIMEOUT")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .unwrap_or(10);
    let yara_rules_file = env::var("YARA_RULES_FILE").expect("please set YARA_RULES_FILE env var");
    if !Path::new(&yara_rules_file).is_file() {
        panic!("YARA_RULES_FILE is not a file")
    }

    thread::spawn(move || {
        if notify.send(id).is_err() {
            return;
        }
        while let Ok(file) = in_queue.recv() {
            let (tx, rx): (Sender<String>, Receiver<String>) = channel();
            let mut out_file = file.clone();
            out_file.push_str(".json");
            let f = file.clone();
            let y = yara_rules_file.clone();
            thread::spawn(move || tx.send(process_file(f, y)).unwrap());
            match rx.recv_timeout(Duration::from_secs(timeout)) {
                Ok(result) => write_result_file(out_file, result),
                _ => println!("ERROR: file {} timeout or panic", &file),
            }
            if notify.send(id).is_err() {
                break;
            }
        }
    })
}

fn write_result_file(dest: String, content: String) {
    let err_msg = format!("can not write result file {}", &dest);
    let mut buffer = File::create(dest).expect(&err_msg);
    buffer.write_all(content.as_bytes()).expect(&err_msg);
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let usage = format!(
        "Usage: {} <yara_rules_file> <input_dir>",
        args.get(0).unwrap()
    );
    let workdir = Path::new(args.get(1).expect(&usage));
    if !workdir.is_dir() {
        panic!("{}", usage)
    }

    let n_workers = num_cpus::get();
    let mut workers = Vec::with_capacity(n_workers);
    let (nf_tx, nf_rx) = channel();
    for n in 0..n_workers {
        let (tx, rx) = channel();
        workers.push((tx, spawn_worker(n, rx, nf_tx.clone())))
    }

    for entry in workdir
        .read_dir()
        .expect("failed to read input dir")
        .flatten()
    {
        let file = entry.path().display().to_string();
        println!("processing {}", &file);
        let w = nf_rx.recv().expect("workers drained out");
        workers
            .get(w)
            .unwrap()
            .0
            .send(file)
            .unwrap_or_else(|_| panic!("worker {} died unexpectedly", w))
    }

    println!("Waiting for workers to finish...");
    drop(nf_rx);
    for worker in workers {
        drop(worker.0);
        worker.1.join().unwrap()
    }
}
