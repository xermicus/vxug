use r2pipe::{R2Pipe, R2PipeSpawnOptions};
use serde::Serialize;
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use std::{env, path::PathBuf};

#[derive(Serialize, Default)]
struct FileInfo {
    #[serde(skip_serializing)]
    pub path: String,
    pub error: Vec<&'static str>,
    pub name: String,
    pub sha256: String,
    pub magic: Vec<String>,
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
#[derive(Serialize)]
struct ImportInfo {
    pub lib: String,
    pub name: String,
}

#[derive(Serialize)]
struct BlockInfo {
    pub name: String,
    pub size: u64,
    pub ssdeep: Option<String>,
    pub entropy: Option<f32>,
}

#[derive(Serialize)]
struct Zignature {
    pub function: BlockInfo,
    pub bytes: String,
    pub mask: String,
    pub bbsum: u64,
    pub addr: u64,
    pub n_vars: u64,
}

fn jstr(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

impl FileInfo {
    fn new(path: String) -> Self {
        FileInfo {
            path: path.clone(),
            name: path.split('/').last().unwrap().to_string(),
            ..Default::default()
        }
    }

    fn sha256(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("itj") {
            Ok(json) => {
                self.sha256 = jstr(&json["sha256"]);
            }
            _ => self.error.push("sha256 hash"),
        }
        self
    }

    fn magic(&mut self, r2: &mut R2Pipe) -> &mut Self {
        let _ = r2.cmd("e search.from = 0");
        let _ = r2.cmd("e search.to = 0x3ff");
        match r2.cmdj("/mj") {
            Ok(json) => {
                if let Value::Array(magics) = json {
                    for magic in magics {
                        self.magic.push(jstr(&magic["info"]))
                    }
                }
            }
            _ => self.error.push("magic"),
        }
        self
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
        match r2.cmdj("iSj entropy,ssdeep") {
            Ok(json) => {
                if let Value::Array(sections) = &json["sections"] {
                    for section in sections {
                        let name = jstr(&section["name"]);
                        if name.is_empty() {
                            continue;
                        }
                        let size = match section["size"].as_u64() {
                            Some(v) => v,
                            _ => continue,
                        };
                        let entropy = jstr(&section["entropy"]).parse::<f32>().ok();
                        let ssdeep = hex::decode(jstr(&section["ssdeep"]).trim_end_matches("00"))
                            .ok()
                            .and_then(|buf| String::from_utf8(buf).ok());
                        self.sections.push(BlockInfo {
                            name,
                            size,
                            ssdeep,
                            entropy,
                        })
                    }
                }
            }
            _ => self.error.push("sections"),
        }
        self
    }

    fn segments(&mut self, r2: &mut R2Pipe) -> &mut Self {
        match r2.cmdj("iSSj entropy,ssdeep") {
            Ok(json) => {
                if let Value::Array(segments) = &json["segments"] {
                    for segment in segments {
                        let name = jstr(&segment["name"]);
                        if name.is_empty() {
                            continue;
                        }
                        let size = match segment["size"].as_u64() {
                            Some(v) => v,
                            _ => continue,
                        };
                        let entropy = jstr(&segment["entropy"]).parse::<f32>().ok();
                        let ssdeep = hex::decode(jstr(&segment["ssdeep"]).trim_end_matches("00"))
                            .ok()
                            .and_then(|buf| String::from_utf8(buf).ok());
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
                            .map(|v| v.trim().to_string());
                        let entropy = r2
                            .cmd(&format!("ph entropy {} @ {}", size, name))
                            .ok()
                            .and_then(|v| v.trim().parse::<f32>().ok());
                        let function = BlockInfo {
                            name,
                            size,
                            ssdeep,
                            entropy,
                        };
                        self.zignatures.push(Zignature {
                            function,
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

    fn anal_basic(&mut self, yara_rules_file: String) {
        let mut r2 = match spawn_r2(&self.path) {
            Ok(v) => v,
            Err(e) => {
                self.error.push(e);
                return;
            }
        };
        self.info(&mut r2)
            .sha256(&mut r2)
            .magic(&mut r2)
            .imports(&mut r2)
            .strings(&mut r2)
            .sections(&mut r2)
            .segments(&mut r2)
            .links(&mut r2)
            .yara(yara_rules_file);
        r2.close();
    }

    fn anal_advanced(&mut self) {
        let mut r2 = match spawn_r2(&self.path) {
            Ok(v) => v,
            Err(e) => {
                self.error.push(e);
                return;
            }
        };
        self.zignatures(&mut r2);
        r2.close();
    }
}

fn spawn_r2(path: &str) -> Result<R2Pipe, &'static str> {
    R2Pipe::spawn(
        path,
        Some(R2PipeSpawnOptions {
            exepath: "r2".to_string(),
            args: vec!["-Q", "-S", "-2"],
        }),
    )
    .map_err(|_| "{\"error\": \"radare2 spawn fail\"}")
}

fn spawn_worker(
    id: usize,
    in_queue: Receiver<String>,
    notify: Sender<usize>,
    out_dir: PathBuf,
) -> thread::JoinHandle<()> {
    let timeout = env::var("WORKER_TIMEOUT")
        .unwrap_or_else(|_| "10".to_string())
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
            let mut info = FileInfo::new(file.clone());
            let mut out_file = out_dir.clone();
            out_file.push(format!("{}.json", &info.name));

            let (tx, rx): (Sender<FileInfo>, Receiver<FileInfo>) = channel();
            let y = yara_rules_file.clone();
            thread::spawn(move || {
                info.anal_basic(y);
                let _ = tx.send(info);
            });
            let mut basic = rx.recv_timeout(Duration::from_secs(timeout));

            let (tx_a, rx_a): (Sender<FileInfo>, Receiver<FileInfo>) = channel();
            let mut info = FileInfo::new(file.clone());
            thread::spawn(move || {
                info.anal_advanced();
                let _ = tx_a.send(info);
            });
            let advanced = rx_a.recv_timeout(Duration::from_secs(timeout));
            if basic.is_err() {
                // maybe basic info now finished
                basic = rx
                    .try_recv()
                    .map_err(|_| std::sync::mpsc::RecvTimeoutError::Timeout)
            }

            match (basic, advanced) {
                (Ok(mut b), Ok(a)) => {
                    b.zignatures = a.zignatures;
                    write_result_file(
                        out_file.as_path(),
                        &serde_json::to_string(&b).expect("serfail"),
                    );
                }
                (Ok(mut b), Err(_)) => {
                    b.error.push("advanced analysis timeout or panic");
                    write_result_file(&out_file, &serde_json::to_string(&b).expect("serfail"))
                }
                (Err(_), Ok(mut a)) => {
                    a.error.push("basic analysis timeout or panic");
                    write_result_file(&out_file, &serde_json::to_string(&a).expect("serfail"))
                }
                _ => write_result_file(
                    &out_file,
                    "{\"error\": \"timeout or panic during analysis\"}",
                ),
            }

            if notify.send(id).is_err() {
                break;
            }
        }
    })
}

fn write_result_file(dest: &Path, content: &str) {
    let err_msg = format!("can not write result file {}", dest.display());
    let mut buffer = File::create(dest).expect(&err_msg);
    buffer.write_all(content.as_bytes()).expect(&err_msg);
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let usage = format!("Usage: {} <input_dir> <output_dir>", args.get(0).unwrap());
    let workdir = Path::new(args.get(1).expect(&usage));
    let outdir = Path::new(args.get(2).expect(&usage));
    if !workdir.is_dir() || !outdir.is_dir() {
        panic!("{}", usage)
    }

    let n_workers = num_cpus::get() * 2;
    let mut workers = Vec::with_capacity(n_workers);
    let (nf_tx, nf_rx) = channel();
    for n in 0..n_workers {
        let (tx, rx) = channel();
        workers.push((tx, spawn_worker(n, rx, nf_tx.clone(), outdir.to_path_buf())))
    }

    let mut count: usize = 0;
    let start = Instant::now();
    for entry in workdir
        .read_dir()
        .expect("failed to read input dir")
        .flatten()
    {
        count += 1;
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

    println!("waiting for workers to finish ...");
    drop(nf_rx);
    for worker in workers {
        drop(worker.0);
        worker.1.join().unwrap()
    }

    let stop = start.elapsed().as_secs();
    println!(
        "done {} samples in {}s ({:.2} samples/s)",
        count,
        stop,
        count as f64 / stop as f64
    )
}
