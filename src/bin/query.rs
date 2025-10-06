use libbonjour::{query_record, RecordType};
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <hostname> [record_type]", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} example.com", args[0]);
        eprintln!("  {} example.com A     # Query A record", args[0]);
        eprintln!("  {} example.com AAAA  # Query AAAA record", args[0]);
        eprintln!("  {} example.com TXT   # Query TXT record", args[0]);
        process::exit(1);
    }

    let hostname = &args[1];
    let record_type = if args.len() > 2 {
        match args[2].to_uppercase().as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "TXT" => RecordType::TXT,
            "MX" => RecordType::MX,
            "PTR" => RecordType::PTR,
            "SRV" => RecordType::SRV,
            "CNAME" => RecordType::CNAME,
            "NS" => RecordType::NS,
            _ => {
                eprintln!("Unknown record type: {}", args[2]);
                process::exit(1);
            }
        }
    } else {
        RecordType::A
    };

    println!("Querying {} for record type {:?}", hostname, record_type);

    let client = match query_record(hostname, record_type) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to initiate query: {:?}", e);
            process::exit(1);
        }
    };

    println!("Query started successfully. Entering the result processing loop...");

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        match client.process_result() {
            Ok(()) => {
                println!("Query processed successfully");
            }
            Err(e) => {
                eprintln!("Error processing query result: {:?}", e);
            }
        }
    }
}
