use base64::prelude::*;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use t3_domain::entity::license::{License, LicensePayload, LicenseTier};
use rand::rngs::OsRng;
use std::env;
use std::fs;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("========================================================");
        println!("          t3Bridge - Commercial License Generator       ");
        println!("========================================================");
        println!("Usage:");
        println!("  licgen keygen                          -> Generates new Keypair");
        println!("  licgen issue <customer> <hwid> <nodes> [days] -> Issues signed license");
        println!("Example:");
        println!("  licgen issue \"ABC Traders\" \"T3-12AB-34CD-56EF\" 5 365");
        return Ok(());
    }

    match args[1].as_str() {
        "keygen" => {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();

            let priv_bytes = signing_key.to_bytes();
            fs::write("master_private.key", priv_bytes)?;

            println!("\n[+] Successfully generated 'master_private.key'!");
            println!("[!] KEEP 'master_private.key' SECRET AND NEVER SHARE IT.");
            println!("\nEmbed this Public Key in the client software (Rust code):");
            println!("pub const EMBEDDED_PUBLIC_KEY: [u8; 32] = {:?};\n", verifying_key.to_bytes());
        }

        "issue" => {
            if args.len() < 5 {
                eprintln!("Error: Missing arguments for issue.");
                eprintln!("Usage: licgen issue <customer> <hwid> <nodes> [days]");
                return Ok(());
            }

            let customer = &args[2];
            let hwid = &args[3];
            let nodes: u32 = args[4].parse().unwrap_or(3);
            let days: Option<i64> = if args.len() >= 6 {
                Some(args[5].parse().unwrap_or(365))
            } else {
                None
            };

            if !fs::metadata("master_private.key").is_ok() {
                eprintln!("[!] 'master_private.key' not found! Run 'licgen keygen' first.");
                return Ok(());
            }

            let priv_bytes: [u8; 32] = fs::read("master_private.key")?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid master_private.key size! Must be 32 bytes."))?;

            let signing_key = SigningKey::from_bytes(&priv_bytes);

            let now = Utc::now().timestamp();
            let expires_at = days.map(|d| now + (d * 86400));

            let payload = LicensePayload {
                license_id: format!("LIC-{}", &uuid_preview()),
                customer_name: customer.clone(),
                hardware_id: hwid.clone(),
                tier: if nodes > 10 { LicenseTier::Enterprise } else { LicenseTier::Standard },
                max_nodes: nodes,
                issued_at: now,
                expires_at,
            };

            let payload_json = serde_json::to_string(&payload)?;
            let signature = signing_key.sign(payload_json.as_bytes());
            let signature_base64 = BASE64_STANDARD.encode(signature.to_bytes());

            let license = License::new(payload, signature_base64);
            let license_json = serde_json::to_string_pretty(&license)?;

            println!("\n================ GENERATED LICENSE KEY ================");
            println!("{}", license_json);
            println!("=======================================================\n");

            let filename = format!("license_{}.json", customer.replace(' ', "_"));
            fs::write(&filename, &license_json)?;
            println!("[+] Saved to file: {}", filename);
        }

        _ => {
            eprintln!("Unknown command: {}", args[1]);
        }
    }

    Ok(())
}

fn uuid_preview() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:04X}-{:04X}", rng.gen::<u16>(), rng.gen::<u16>())
}
