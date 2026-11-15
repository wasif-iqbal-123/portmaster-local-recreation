use portmaster_core::engine::Engine;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/download-all-data".to_string());
    let engine = Arc::new(Engine::load_from(std::path::PathBuf::from(dir)));
    engine.download_all_filters().expect("could not start download");

    loop {
        let snapshot = engine.snapshot();
        if !snapshot.update_running {
            let mut entries = 0usize;
            let mut errors = 0usize;
            for source in &snapshot.sources {
                entries += source.count;
                if source.error.is_some() {
                    errors += 1;
                    println!("ERROR {}: {}", source.id, source.error.as_deref().unwrap());
                } else {
                    println!("OK {}: {} entries", source.id, source.count);
                }
            }
            println!("DONE: {} sources, {} entries, {} errors", snapshot.sources.len(), entries, errors);
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
}
