use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use serde::Serialize;
use serde_json::Value;
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
    pub error: Vec<&'static str>,
    pub name: String,
    pub arch: String,
    pub size: u64,
    pub format: String,
    pub bintype: String,
    pub compiler: String,
    pub lang: String,
    pub machine: String,
    pub os: String,
    pub strings: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub sections: Vec<BlockInfo>,
    pub segments: Vec<BlockInfo>,
    pub links: Vec<String>,
    pub zignatures: Vec<Zignature>,
    pub yara: String,
}

fn jstr(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

impl FileInfo {
    fn new(path: String) -> Self {
        FileInfo {
            name: path.split('/').last().unwrap().to_string(),
            ..Default::default()
        }
    }

    fn info(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("ij") {
            Ok(json) => {
                self.format = jstr(&json["core"]["format"]);
                self.arch = jstr(&json["bin"]["arch"]);
                if let Some(size) = json["bin"]["size"].as_u64() {
                    self.size = size;
                }
                self.bintype = jstr(&json["bin"]["bintype"]);
                self.compiler = jstr(&json["bin"]["compiler"]);
                self.lang = jstr(&json["bin"]["lang"]);
                self.machine = jstr(&json["bin"]["machine"]);
                self.os = jstr(&json["bin"]["os"]);
            }
            _ => self.error.push("info"),
        }
        self
    }

    fn strings(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("izj") {
            Ok(json) => {
                if let Value::Array(strings) = json {
                    for string in strings {
                        self.strings.push(jstr(&string["string"]))
                    }
                }
            }
            _ => self.error.push("strings"),
        }
        self
    }

    fn imports(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iij") {
            Ok(json) => {
                if let Value::Array(imports) = json {
                    for import in imports {
                        self.imports.push(ImportInfo {
                            name: jstr(&import["name"]),
                            lib: jstr(&import["lib"]),
                        })
                    }
                }
            }
            _ => self.error.push("imports"),
        }
        self
    }

    fn sections(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iSj") {
            Ok(json) => {
                if let Value::Array(sections) = json {
                    for section in sections {
                        let name = jstr(&section["name"]);
                        if name.is_empty() {
                            continue;
                        }
                        let size = match section["size"].as_u64() {
                            Some(v) => v,
                            _ => continue,
                        };
                        self.sections.push(BlockInfo {
                            name,
                            size,
                            ..Default::default()
                        })
                    }
                }
            }
            _ => self.error.push("sections"),
        }
        self
    }

    fn segments(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iSSj") {
            Ok(json) => {
                if let Value::Array(segments) = json {
                    for segment in segments {
                        let name = jstr(&segment["name"]);
                        if name.is_empty() {
                            continue;
                        }
                        let size = match segment["size"].as_u64() {
                            Some(v) => v,
                            _ => continue,
                        };
                        let entropy = r2
                            .cmd(&format!("ph entropy {} @ segment.{}", size, name))
                            .ok()
                            .and_then(|v| v.trim().parse::<f32>().ok());
                        let ssdeep = r2
                            .cmd(&format!("ph ssdeep {} @ segment.{}", size, name))
                            .ok()
                            .and_then(|v| Some(v.trim().to_string()));
                        self.segments.push(BlockInfo {
                            name,
                            size,
                            ssdeep,
                            entropy,
                        })
                    }
                }
            }
            _ => self.error.push("segments"),
        }
        self
    }

    fn links(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("ilj") {
            Ok(json) => {
                if let Value::Array(links) = json {
                    for link in links {
                        self.links.push(jstr(&link))
                    }
                }
            }
            _ => self.error.push("strings"),
        }
        self
    }

    fn yara(&mut self, yara_rules_file: String) -> &mut Self {
        let err = "yara processing error".to_string();
        self.yara = match Command::new("yara")
            .arg("-f")
            .arg("-w")
            .arg(&yara_rules_file)
            .arg(&self.name)
            .output()
        {
            Ok(result) => String::from_utf8(result.stdout).unwrap_or(err),
            _ => err,
        };
        self
    }

    fn zignatures(&mut self, r2: &mut R2Pipe) -> &mut Self {
        let _ = r2.cmd("aa;zaF");
        match r2.cmdj("zj") {
            Ok(json) => {
                if let Value::Array(zignatures) = json {
                    for zign in zignatures {
                        let name = jstr(&zign["name"]);
                        let bytes = jstr(&zign["bytes"]);
                        let size = bytes.len() as u64;
                        let mask = jstr(&zign["mask"]);
                        let bbsum = zign["graph"]["bbsum"].as_u64().unwrap_or(0);
                        let addr = zign["addr"].as_u64().unwrap_or(0);
                        let n_vars = match zign["vars"].as_array() {
                            Some(v) => v.len() as u64,
                            _ => 0,
                        };
                        let ssdeep = r2
                            .cmd(&format!("ph ssdeep {} @ {}", size, name))
                            .ok()
                            .and_then(|v| Some(v.trim().to_string()));
                        let entropy = r2
                            .cmd(&format!("ph entropy {} @ {}", size, name))
                            .ok()
                            .and_then(|v| v.trim().parse::<f32>().ok());
                        let block = BlockInfo {
                            name,
                            size,
                            ssdeep,
                            entropy,
                        };
                        self.zignatures.push(Zignature {
                            block,
                            bytes,
                            mask,
                            bbsum,
                            addr,
                            n_vars,
                        })
                    }
                }
            }
            _ => self.error.push("strings"),
        }

        self
    }

    fn finish(&self, mut r2: R2Pipe) -> Result<String, serde_json::Error> {
        r2.close();
        serde_json::to_string(self)
    }
}

#[derive(Serialize)]
struct ImportInfo {
    pub lib: String,
    pub name: String,
}

#[derive(Serialize, Default)]
struct BlockInfo {
    pub name: String,
    pub size: u64,
    pub ssdeep: Option<String>,
    pub entropy: Option<f32>,
}

#[derive(Serialize)]
struct Zignature {
    pub block: BlockInfo,
    pub bytes: String,
    pub mask: String,
    pub bbsum: u64,
    pub addr: u64,
    pub n_vars: u64,
}

fn process_file(path: String, yara_rules_file: String) -> String {
    let mut r2 = match R2Pipe::spawn(
        &path,
        Some(R2PipeSpawnOptions {
            exepath: "r2".to_string(),
            args: vec!["-Q", "-S", "-2"],
        }),
    ) {
        Ok(pipe) => pipe,
        _ => return "{\"error\": \"radare2 spawn fail\"}".to_string(),
    };
    FileInfo::new(path)
        .info(&mut r2)
        .imports(&mut r2)
        .strings(&mut r2)
        .sections(&mut r2)
        .segments(&mut r2)
        .links(&mut r2)
        .zignatures(&mut r2)
        .yara(yara_rules_file)
        .finish(r2)
        .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
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
                _ => {
                    println!("ERROR: file {} timeout or panic", &file);
                    write_result_file(
                        out_file,
                        "{\"error\": \"timeout or panic during analysis\"}".to_string(),
                    )
                }
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
