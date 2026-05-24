//! Torture `Module::init_from_reader` + section iteration against I/O
//! fault injection on a valid WASM module.

use wsc_torture_runner::torture_io;
use wsc_verify_core::wasm_module::Module;

fn main() {
    // Minimal valid WASM module: magic + version + an empty custom section.
    // Layout: 8-byte header, then section ID 0x00 (custom), section size,
    // name-length varint, name bytes, payload (empty).
    let module_bytes: &[u8] = &[
        // magic + version
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
        // section id 0 (custom)
        0x00,
        // section size: 5 bytes follow (name_len + name + empty payload)
        0x05,
        // name_len: 4
        0x04,
        // name: "test"
        b't', b'e', b's', b't',
    ];

    // Torture: at every byte offset, force a Read::read() error. Module
    // parsing must surface a clean Err without panicking.
    torture_io("Module::init_from_reader + iterate", module_bytes, |reader| {
        let stream = Module::init_from_reader(reader)?;
        for section in Module::iterate(stream)? {
            // The `?` here forces every section-parsing error path to be
            // exercised when faults land mid-section.
            let _section = section?;
        }
        Ok::<(), wsc_verify_core::CoreError>(())
    });

    println!("\n✔ Module::init_from_reader survived I/O torture at every byte offset.");
}
