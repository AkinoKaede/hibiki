fn main() {
    println!("cargo:rerun-if-changed=proto");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let mut config = prost_build::Config::new();
    config
        .protoc_executable(protoc_bin_vendored::protoc_bin_path().expect("bundled protoc"))
        .type_attribute(".", "#[derive(zeroize::Zeroize)]")
        .type_attribute(
            ".hibiki.v2.ResponseResult.kind",
            "#[allow(clippy::large_enum_variant)]",
        )
        .file_descriptor_set_path(output.join("hibiki-v2.bin"));
    let schema = config
        .load_fds(
            &[
                "proto/membership.proto",
                "proto/operation.proto",
                "proto/control.proto",
                "proto/relay.proto",
                "proto/session.proto",
            ],
            &["proto"],
        )
        .expect("compile hibiki/2 schema");
    // prost creates local nested values before attaching them to their parent.
    // Clear their owned strings/bytes on every drop, including partial decode errors.
    // Scalar-only generated messages are Copy and have no secret allocations.
    for message in schema.file.iter().flat_map(|file| &file.message_type) {
        if message.field.iter().any(|field| {
            matches!(
                field.r#type(),
                prost_types::field_descriptor_proto::Type::Bytes
                    | prost_types::field_descriptor_proto::Type::String
            )
        }) {
            config.message_attribute(
                format!(".hibiki.v2.{}", message.name.as_deref().unwrap()),
                "#[derive(zeroize::ZeroizeOnDrop)]",
            );
        }
    }
    config.compile_fds(schema).expect("generate hibiki/2 codec");
    write_shapes(&output);
}

// Borrow-only preflight rules keep duplicate fields from reallocating a decoded
// secret buffer and bound allocation amplification before prost materializes it.
fn write_shapes(output: &std::path::Path) {
    use prost::Message;
    use prost_types::field_descriptor_proto::{Label, Type};
    let bytes = std::fs::read(output.join("hibiki-v2.bin")).unwrap();
    let schema = prost_types::FileDescriptorSet::decode(bytes.as_slice()).unwrap();
    let messages: Vec<_> = schema
        .file
        .iter()
        .flat_map(|file| &file.message_type)
        .collect();
    let mut code = String::from("static SHAPES: &[Shape] = &[\n");
    for message in &messages {
        assert!(
            message.field.len() <= 64 && message.oneof_decl.len() <= 64,
            "preflight masks require at most 64 fields/oneofs per message"
        );
        code.push_str(&format!(
            "Shape {{ name: {:?}, fields: &[\n",
            message.name.as_deref().unwrap()
        ));
        for field in &message.field {
            let tag = field.number.unwrap();
            let repeated = field.label() == Label::Repeated;
            let nested = if field.r#type() == Type::Message {
                let name = field
                    .type_name
                    .as_deref()
                    .unwrap()
                    .strip_prefix(".hibiki.v2.")
                    .unwrap();
                format!(
                    "Some({})",
                    messages
                        .iter()
                        .position(|message| message.name.as_deref() == Some(name))
                        .unwrap()
                )
            } else {
                "None".to_owned()
            };
            let wire = match field.r#type() {
                Type::Message | Type::String | Type::Bytes => 2,
                Type::Fixed64 | Type::Sfixed64 | Type::Double => 1,
                Type::Fixed32 | Type::Sfixed32 | Type::Float => 5,
                _ => 0,
            };
            let utf8 = field.r#type() == Type::String;
            code.push_str(&format!("Field {{ tag: {tag}, repeated: {repeated}, oneof: {:?}, nested: {nested}, wire: {wire}, utf8: {utf8} }},\n",field.oneof_index));
        }
        code.push_str("] },\n");
    }
    code.push_str("];\n");
    std::fs::write(output.join("wire-shapes.rs"), code).unwrap();
}
