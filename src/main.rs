use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

const TIMEOUT: u64 = 1;

fn process_file(path: String) -> String {
    let failure = "{\"error\": \"unknown error\"}".to_string();

    failure
}

fn spawn_worker(
    id: usize,
    in_queue: Receiver<String>,
    notify: Sender<usize>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _ = notify.send(id);
        while let Ok(file) = in_queue.recv() {
            let (tx, rx): (Sender<String>, Receiver<String>) = channel();
            let mut out_file = file.clone();
            out_file.push_str(".json");
            let f = file.clone();
            thread::spawn(move || tx.send(process_file(f)).unwrap());
            match rx.recv_timeout(Duration::from_secs(TIMEOUT)) {
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
    let usage = format!("Usage: {} <input_dir> <output_dir>", args.get(0).unwrap());
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
