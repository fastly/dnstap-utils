// Copyright 2021 Fastly, Inc.

fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["src/dnstap.proto"], &["src/"])?;
    Ok(())
}
