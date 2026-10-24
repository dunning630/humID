//! Retention (SERVER.md §5): every table of every unit has a rule, and the rules run.

mod common;

use common::*;
use humid_server::db;
use humid_server::retention;
use humid_server::testkit::Phone;
use humid_server::testkit::cluster::{App, Cluster};
use humid_server::unit::ms;
use humid_server::wire::B64;
use serde_json::{Value, json};

#[tokio::test]
async fn every_table_of_every_unit_has_a_rule() {
    for (unit, migrations, rules) in [
        (
            "core",
            humid_server::core::MIGRATIONS,
            humid_server::core::RETENTION,
        ),
        (
            "keys",
            humid_server::keys::MIGRATIONS,
            humid_server::keys::RETENTION,
        ),
        (
            "anon",
            humid_server::anon::MIGRATIONS,
            humid_server::anon::RETENTION,
        ),
    ] {
        let (d, schema) = db::test::fresh(unit).await.unwrap();
        d.migrate(unit, migrations).await.unwrap();
        let (without, unknown) = retention::missing(&d, rules).await.unwrap();
        assert!(
            without.is_empty(),
            "{unit}: tables without a retention rule: {without:?}"
        );
        assert!(
            unknown.is_empty(),
            "{unit}: rules for tables that don't exist: {unknown:?}"
        );
        // every rule is valid SQL against the real schema
        retention::run(&d, rules, 0).await.unwrap();
        db::test::drop_schema(&schema).await.unwrap();
    }
}

#[tokio::test]
async fn short_lived_rows_go_and_kept_ones_stay() {
    let c = Cluster::start(|_| {}).await.unwrap();
    let phone = Phone::new().unwrap();
    let mut app = App::new(&c).unwrap();
    app.register(&phone).await.unwrap();
    let (doc, _) = upload(&mut app, &phone, 64).await.unwrap();
    let _ = open(&mut app, &phone, &doc.id).await.unwrap();
    // a link that nobody approves
    let once = humid_server::crypto::KemSecret::generate().unwrap();
    let tablet = phone.sibling().unwrap();
    let _: Value = app.core("POST", "/v1/links", &json!({ "device_vk": B64(tablet.device.public().to_bytes()), "kem_pk": B64(once.public().to_bytes()) })).await.unwrap();

    let count = |t: &'static str| {
        let d = c.core_db().clone();
        async move {
            d.conn()
                .await
                .unwrap()
                .query_one(format!("SELECT count(*) FROM {t}").as_str(), &[])
                .await
                .unwrap()
                .get::<_, i64>(0)
        }
    };
    assert!(count("nonces").await > 0);
    assert_eq!(count("download_tickets").await, 1);
    assert_eq!(count("links").await, 1);
    let ledger_before = count("ledger_entries").await;

    // two days on: sessions, nonces, tickets and links go; the ledger, accounts and objects stay
    let later = c.clock.now() + 2 * ms::DAY + 9 * ms::HOUR;
    retention::run(c.core_db(), humid_server::core::RETENTION, later)
        .await
        .unwrap();
    assert_eq!(count("nonces").await, 0);
    assert_eq!(count("download_tickets").await, 0);
    assert_eq!(count("links").await, 0);
    assert_eq!(count("sessions").await, 0);
    assert_eq!(count("ledger_entries").await, ledger_before);
    assert_eq!(count("objects").await, 1);
    assert_eq!(count("accounts").await, 1);

    // keys: the hourly release log and used proofs go; the share stays
    retention::run(c.keys.db(), humid_server::keys::RETENTION, later)
        .await
        .unwrap();
    assert_eq!(c.keys.count_rows("releases").await.unwrap(), 0);
    assert_eq!(c.keys.count_rows("used_proofs").await.unwrap(), 0);
    assert_eq!(c.keys.count_rows("shares").await.unwrap(), 1);
    c.stop().await.unwrap();
}
