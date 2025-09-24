mod certs_config;

use openssl::pkey::PKey;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::x509::{X509, X509NameBuilder, X509ReqBuilder};
use openssl::hash::MessageDigest;
use openssl::asn1::{Asn1Integer, Asn1Time};
use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use openssl::bn::BigNum;
use std::string::String;
use openssl::pkcs12::Pkcs12;
use crate::certs_config::KmeConfig;

const INTER_KMES_SUBDIR: &'static str = "/inter_kmes/";
const COMPANY_NAME: &'static str = "QuantumVerse Innovation";
const COUNTRY_CODE: &'static str = "FR";

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 2 {
        eprintln!("Usage: {} config.json5", args[0]);
        std::process::exit(1);
    }
    let json5_config_file = &args[1];
    let config_str = match std::fs::read_to_string(json5_config_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Config file reading error {}: {}", json5_config_file, e);
            std::process::exit(1);
        }
    };
    let config: certs_config::CertsConfig = match json5::from_str(&config_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config file parsing error {}: {}", json5_config_file, e);
            std::process::exit(1);
        }
    };

    let _ = std::fs::create_dir(&config.certs_dir);
    if !std::fs::exists(&config.certs_dir).unwrap() || !std::fs::metadata(&config.certs_dir).unwrap().is_dir() {
        eprintln!("Cannot create {} directory", config.certs_dir);
        std::process::exit(1);
    }

    let inter_kmes_subdir_path = config.certs_dir.clone() + INTER_KMES_SUBDIR;
    let _ = std::fs::create_dir(inter_kmes_subdir_path);

    for kme in &config.kmes {
        let kme_subdir_path = config.certs_dir.clone() + "/kme-" + kme.id.to_string().as_str() + "-local-zone/";
        let _ = std::fs::create_dir(&kme_subdir_path);

        generate_zone_certificates(&kme_subdir_path, &kme, config.cert_exp_time_days, config.ca_cert_exp_time_days);

    }

}

fn generate_zone_certificates(directory: &str, kme_config: &KmeConfig, cert_exp_time_days: usize, ca_cert_exp_time_days: usize) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ca_ec = EcKey::generate(&group).unwrap();
    let ca_pkey = PKey::from_ec_key(ca_ec).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("C", COUNTRY_CODE).unwrap();
    name_builder.append_entry_by_text("O", COMPANY_NAME).unwrap();
    name_builder.append_entry_by_text("CN", format!("KME{} local CA", kme_config.id).as_str()).unwrap();
    let ca_name = name_builder.build();

    let mut ca_builder = X509::builder().unwrap();
    ca_builder.set_version(2).unwrap();
    ca_builder.set_subject_name(&ca_name).unwrap();
    ca_builder.set_issuer_name(&ca_name).unwrap();
    ca_builder.set_pubkey(&ca_pkey).unwrap();
    ca_builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    ca_builder
        .set_not_after(&Asn1Time::days_from_now(ca_cert_exp_time_days as u32).unwrap())
        .unwrap();
    ca_builder.set_serial_number(&gen_random_serial()).unwrap();
    ca_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
    let ca_cert = ca_builder.build();

    File::create(format!("{}/ca.crt", directory))
        .unwrap()
        .write_all(&ca_cert.to_pem().unwrap())
        .unwrap();
    File::create(format!("{}/ca.key", directory))
        .unwrap()
        .write_all(&ca_pkey.private_key_to_pem_pkcs8().unwrap())
        .unwrap();

    for sae in kme_config.saes.iter() {
        let client_ec = EcKey::generate(&group).unwrap();
        let client_pkey = PKey::from_ec_key(client_ec).unwrap();

        let mut client_name_builder = X509NameBuilder::new().unwrap();
        client_name_builder.append_entry_by_text("C", COUNTRY_CODE).unwrap();
        client_name_builder.append_entry_by_text("O", COMPANY_NAME).unwrap();
        client_name_builder
            .append_entry_by_text("CN", &format!("SAE-{}", sae.id))
            .unwrap();
        let client_name = client_name_builder.build();

        let mut client_builder = X509::builder().unwrap();
        client_builder.set_version(2).unwrap();
        client_builder.set_subject_name(&client_name).unwrap();
        client_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        client_builder.set_pubkey(&client_pkey).unwrap();
        client_builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        client_builder
            .set_not_after(&Asn1Time::days_from_now(cert_exp_time_days as u32).unwrap())
            .unwrap();

        // Utiliser client_certificate_serial fourni dans la config
        let serial = Asn1Integer::from_bn(
            BigNum::from_slice(&sae.client_certificate_serial)
                .unwrap()
                .as_ref(),
        )
            .unwrap();
        client_builder.set_serial_number(&serial).unwrap();

        client_builder
            .sign(&ca_pkey, MessageDigest::sha256())
            .unwrap();
        let client_cert = client_builder.build();

        // Sauvegarde PEM
        File::create(format!("{}/client_{}_cert.pem", directory, sae.id))
            .unwrap()
            .write_all(&client_cert.to_pem().unwrap())
            .unwrap();
        File::create(format!("{}/client_{}_key.pem", directory, sae.id))
            .unwrap()
            .write_all(&client_pkey.private_key_to_pem_pkcs8().unwrap())
            .unwrap();

        // Sauvegarde PKCS#12 (pfx)
        let pkcs12 = Pkcs12::builder()
            .build(
                sae.client_pfx_certificate_password.as_str(),               // mot de passe du pfx
                &format!("SAE-{}", sae.id), // friendly name
                &client_pkey,
                &client_cert,
            )
            .unwrap();
        let der = pkcs12.to_der().unwrap();
        File::create(format!("{}/client_{}.pfx", directory, sae.id))
            .unwrap()
            .write_all(&der)
            .unwrap();

        File::create(format!("{}/client_{}.crt", directory, sae.id))
            .unwrap()
            .write_all(&client_cert.to_pem().unwrap())
            .unwrap();
        File::create(format!("{}/client_{}.key", directory, sae.id))
            .unwrap()
            .write_all(&client_pkey.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
    }

    let server_ec = EcKey::generate(&group).unwrap();
    let server_pkey = PKey::from_ec_key(server_ec).unwrap();

    let mut server_name_builder = X509NameBuilder::new().unwrap();
    server_name_builder.append_entry_by_text("C", COUNTRY_CODE).unwrap();
    server_name_builder.append_entry_by_text("O", COMPANY_NAME).unwrap();
    server_name_builder
        .append_entry_by_text("CN", kme_config.addr_for_saes.as_str())
        .unwrap();
    let server_name = server_name_builder.build();

    // CSR serveur
    let mut server_req_builder = X509ReqBuilder::new().unwrap();
    server_req_builder.set_pubkey(&server_pkey).unwrap();
    server_req_builder.set_subject_name(&server_name).unwrap();
    server_req_builder.sign(&server_pkey, MessageDigest::sha256()).unwrap();
    let server_req = server_req_builder.build();

    // Certificat serveur signé par le CA
    let mut server_builder = X509::builder().unwrap();
    server_builder.set_version(2).unwrap();
    server_builder.set_subject_name(server_req.subject_name()).unwrap();
    server_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    server_builder.set_pubkey(&server_pkey).unwrap();
    server_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    server_builder
        .set_not_after(&Asn1Time::days_from_now(cert_exp_time_days as u32).unwrap())
        .unwrap();
    server_builder.set_serial_number(&gen_random_serial()).unwrap();

    // Signature par le CA
    server_builder.sign(&ca_pkey, MessageDigest::sha256()).unwrap();
    let server_cert = server_builder.build();

    // Sauvegarde en .crt / .key
    File::create(format!("{}/kme_server.crt", directory))
        .unwrap()
        .write_all(&server_cert.to_pem().unwrap())
        .unwrap();
    File::create(format!("{}/kme_server.key", directory))
        .unwrap()
        .write_all(&server_pkey.private_key_to_pem_pkcs8().unwrap())
        .unwrap();

    println!("✅ Certificates generated in {}", directory);
}

fn gen_random_serial() -> Asn1Integer {
    let mut bn = BigNum::new().unwrap();
    bn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    Asn1Integer::from_bn(&bn).unwrap()
}