mod cursor;
mod macho;
mod objc;
mod output;
mod typ;

use macho::MachOFile;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: class-dump <mach-o-file>");
        exit(1);
    }
    let path = &args[args.len() - 1];
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("class-dump: cannot read {}: {}", path, e);
            exit(1);
        }
    };

    let file = match MachOFile::parse(data, path.clone()) {
        Some(f) => f,
        None => {
            eprintln!("class-dump: not a thin Mach-O file (fat not yet supported)");
            exit(1);
        }
    };

    let mut processor = objc::Processor::new(&file);
    let image = processor.process();

    let opts = output::Options { sort_by_name: true, sort_methods: false };
    let text = output::dump(&file, &image, &opts);
    print!("{}", text);
}
