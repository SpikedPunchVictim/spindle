//! Generates `vectors/admin-reply.json` (td-efea19/td-2c9d43): the reply envelope
//! `spindle_helper::admin` emits and `@spindle/admin` decodes. Deterministic; no clock, no I/O
//! beyond writing the file.

use spindle_helper::admin::AdminReply;
use spindle_proto::canonical::CborValue;
use std::fs;
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn case(name: &str, description: &str, reply: &AdminReply) -> String {
    format!(
        "    {{\n      \"name\": {name:?},\n      \"description\": {description:?},\n      \
         \"canonical_cbor_hex\": \"{}\"\n    }}",
        hex(&reply.to_canonical_bytes())
    )
}

fn main() {
    let cases = [
        case(
            "ok_no_result",
            "A successful command with no value (set_mode, suspend_host, ...).",
            &AdminReply::Ok { result: None },
        ),
        case(
            "ok_with_result",
            "A successful read (list_hosts/read_audit_log); result is an opaque CBOR value.",
            &AdminReply::Ok {
                result: Some(CborValue::text("ready")),
            },
        ),
        case(
            "refused_code_only",
            "A replay refusal: the code is the machine-readable reason and no human detail is added.",
            &AdminReply::Refused {
                code: "replay".to_string(),
                message: None,
            },
        ),
        case(
            "refused_code_and_message",
            "A malformed-argument refusal with a human-readable detail.",
            &AdminReply::Refused {
                code: "invalid_args".to_string(),
                message: Some("host_fp must be 32 bytes".to_string()),
            },
        ),
    ];
    let doc = format!(
        "{{\n  \"artifact\": \"AdminReply\",\n  \"description\": \"Reply envelope for \
         registry.admin.> (A3b, td-efea19): {{v, ok, result?}} or {{v, ok, error:{{code,message?}}}}. \
         Not a signed A7b artifact; the command is signed, the reply is not.\",\n  \"cases\": [\n{}\n  \
         ]\n}}\n",
        cases.join(",\n")
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
        .join("admin-reply.json");
    fs::write(&path, doc).expect("write admin-reply.json");
    println!("wrote {}", path.display());
}
