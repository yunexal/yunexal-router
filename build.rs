use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/xdp_shield.bpf.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let obj_path = out_dir.join("xdp_shield.o");

    let compiler = ["clang-19", "clang"]
        .into_iter()
        .find(|c| Command::new(c).arg("--version").output().is_ok())
        .expect("clang or clang-19 required to compile bpf/xdp_shield.bpf.c");

    let status = Command::new(compiler)
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include",
            "-I/usr/include/x86_64-linux-gnu",
            "-c",
            "bpf/xdp_shield.bpf.c",
            "-o",
        ])
        .arg(&obj_path)
        .status()
        .expect("failed to execute clang");

    if !status.success() {
        panic!("clang BPF compilation failed with status {status}");
    }
}
