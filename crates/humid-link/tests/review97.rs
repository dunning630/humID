//! Regression tests for the PR #97 review, humid-link side (each was a probe that passed
//! while its finding was present).

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use humid_htp::cert::Bundle;
use humid_htp::frame::{self, Kind};
use humid_htp::msg::Method;
use humid_htp::server::{Config, Server};
use humid_htp::{Code, Unit, label};
use humid_link::{Link, LinkError, NetError, PolicyView, Transport};
use humid_pq2::{DualSigningKey, MlDsaSigningKey};

const NOW: u64 = 1_798_761_600_000;
const DAY: u64 = 86_400_000;

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// Policy files in these tests are `version ‖ production ‖ statement key`.
fn policy_of(p: &[u8], _: Unit) -> Option<PolicyView> {
    let (v, rest) = p.split_first_chunk::<8>()?;
    let (prod, key) = rest.split_first()?;
    Some(PolicyView {
        version: u64::from_be_bytes(*v),
        production: *prod == 1,
        statement_key: key.to_vec(),
    })
}

struct World {
    server: Server,
    root: DualSigningKey,
    st: MlDsaSigningKey,
    bundle: Vec<u8>,
    executed: usize,
    forge_next: bool,
    bundle_override: Option<Vec<u8>>,
    keys_fetched: usize,
    offline: bool,
    now: u64,
}

impl World {
    fn policy(&self, version: u64) -> (Vec<u8>, Vec<u8>) {
        let mut p = version.to_be_bytes().to_vec();
        p.push(1);
        p.extend_from_slice(&self.st.verifying_key().to_bytes());
        let sig = self
            .root
            .sign(label::POLICY, &humid_pq2::encoding::lp(&[&p]).unwrap())
            .unwrap()
            .to_bytes();
        (p, sig)
    }

    fn rekey(&mut self, from: u64, version: u64) {
        let pk = Server::prepare_key(from, from + DAY).unwrap();
        let sig = self
            .st
            .sign(label::KEM_CERT, &pk.to_be_signed(Unit::Core))
            .unwrap()
            .to_bytes();
        let cert = self.server.install_key(pk, &sig).unwrap();
        let (policy, policy_sig) = self.policy(version);
        self.bundle = Bundle {
            policy,
            policy_sig,
            certs: vec![cert],
        }
        .encode();
    }
}

#[derive(Clone)]
struct T(Arc<Mutex<World>>);

impl Transport for T {
    fn call(&mut self, body: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, NetError>> + Send {
        let w = self.0.clone();
        async move {
            let mut w = w.lock().unwrap();
            if w.offline {
                return Err(NetError);
            }
            let now = w.now;
            let r = w.server.receive(&body, now);
            let mut out = r.frames;
            for req in r.ready {
                w.executed += 1;
                let a = w
                    .server
                    .respond(&req.sid, req.head.rid, 200, 0, b"{\"ok\":true}", now)
                    .unwrap();
                out.extend_from_slice(&a);
            }
            let is_record = frame::split(&body)
                .map(|f| f[0].header.kind == Kind::Record)
                .unwrap_or(false);
            if is_record && w.forge_next {
                // front (or anyone on the path) swaps the genuine answer for an
                // unauthenticated error frame
                w.forge_next = false;
                let sid = frame::split(&body).unwrap()[0].header.sid;
                return Ok(frame::error(Unit::Core, sid, Code::SessionUnknown));
            }
            Ok(out)
        }
    }
    fn keys(&mut self) -> impl Future<Output = Result<Vec<u8>, NetError>> + Send {
        let w = self.0.clone();
        async move {
            let mut w = w.lock().unwrap();
            w.keys_fetched += 1;
            Ok(w.bundle_override
                .clone()
                .unwrap_or_else(|| w.bundle.clone()))
        }
    }
}

fn setup() -> (Link<T>, T) {
    let root = DualSigningKey::generate().unwrap();
    let st = MlDsaSigningKey::generate().unwrap();
    let server = Server::new(Config::new(Unit::Core)).unwrap();
    let mut w = World {
        server,
        root,
        st,
        bundle: vec![],
        executed: 0,
        forge_next: false,
        bundle_override: None,
        keys_fetched: 0,
        offline: false,
        now: NOW,
    };
    w.rekey(NOW - 1000, 1);
    let vk = humid_pq2::DualVerifyingKey::from_bytes(&w.root.verifying_key().to_bytes()).unwrap();
    let t = T(Arc::new(Mutex::new(w)));
    let tc = t.clone();
    let link = Link::new(
        Unit::Core,
        vk,
        policy_of,
        t.clone(),
        Box::new(move || tc.0.lock().map(|w| w.now).unwrap_or(NOW)),
    );
    (link, t)
}

/// M-5: one forged unauthenticated `session_unknown` doesn't make the link run a request
/// twice: an authenticated pull finds the genuine answer.
#[test]
fn m5_a_forged_session_unknown_never_runs_a_request_twice() {
    let (mut link, t) = setup();
    block_on(link.connect()).unwrap();
    t.0.lock().unwrap().forge_next = true;
    let r = block_on(link.request(Method::Post, "/v1/links", b"{}"));
    assert!(r.is_ok(), "{:?}", r.err());
    assert_eq!(t.0.lock().unwrap().executed, 1, "executed once");
    assert_eq!(
        link.resumptions(),
        0,
        "the session wasn't dropped on a forged word"
    );
}

/// L-3: a bundle endpoint that answers anything but a bundle (front's 503 JSON while a unit
/// restarts) is `Offline`, not the identity-changed hard stop; a bundle signed by another
/// root still is the hard stop.
#[test]
fn l3_a_transient_error_is_not_identity_changed() {
    let (mut link, t) = setup();
    t.0.lock().unwrap().bundle_override = Some(
        br#"{"error":"unit_unavailable","message":"A service has no HTP/2 key yet."}"#.to_vec(),
    );
    assert_eq!(block_on(link.connect()), Err(LinkError::Offline));
    let forged = {
        let w = t.0.lock().unwrap();
        let mut b = Bundle::decode(&w.bundle).unwrap();
        let other = DualSigningKey::generate().unwrap();
        b.policy_sig = other
            .sign(
                label::POLICY,
                &humid_pq2::encoding::lp(&[&b.policy]).unwrap(),
            )
            .unwrap()
            .to_bytes();
        b.encode()
    };
    t.0.lock().unwrap().bundle_override = Some(forged);
    assert_eq!(block_on(link.connect()), Err(LinkError::IdentityChanged));
}

/// L-3: no answer to a RESUME keeps the ticket: the next unlock resumes.
#[test]
fn l3_offline_during_resume_keeps_the_ticket() {
    let (mut link, t) = setup();
    block_on(link.connect()).unwrap();
    link.lock();
    t.0.lock().unwrap().offline = true;
    assert_eq!(block_on(link.connect()), Err(LinkError::Offline));
    t.0.lock().unwrap().offline = false;
    block_on(link.connect()).unwrap();
    assert_eq!((link.handshakes(), link.resumptions()), (1, 1));
}

/// M-6: past its half life the link fetches the bundle again and uses the new key; an
/// expired certificate is never used.
#[test]
fn m6_the_link_refetches_and_never_uses_an_expired_certificate() {
    let (mut link, t) = setup();
    block_on(link.connect()).unwrap();
    assert_eq!(t.0.lock().unwrap().keys_fetched, 1);
    link.forget();
    {
        let mut w = t.0.lock().unwrap();
        w.now = NOW + DAY / 2 + 1;
        let at = w.now - 1000;
        w.rekey(at, 1);
    }
    block_on(link.connect()).unwrap();
    assert_eq!(
        t.0.lock().unwrap().keys_fetched,
        2,
        "refetched at half life"
    );
    // the server stops serving bundles; a week on the cached certificate is expired
    link.forget();
    {
        let mut w = t.0.lock().unwrap();
        w.now = NOW + 7 * DAY;
        w.bundle_override = Some(b"down".to_vec());
    }
    assert_eq!(block_on(link.connect()), Err(LinkError::Offline));
}

/// L-1: the server's mode surfaces, and an older policy than one the link has accepted is
/// refused, also after the app restarts (the floor is persisted and restored).
#[test]
fn l1_policy_is_forward_only() {
    let (mut link, t) = setup();
    t.0.lock().unwrap().rekey(NOW - 1000, 5);
    block_on(link.connect()).unwrap();
    assert_eq!(link.policy_seen().unwrap().version, 5);
    assert_eq!(link.server_is_production(), Some(true));
    let floor = link.policy_seen().unwrap();
    // the root re-signs an older policy (one naming a retired statement key, say)
    t.0.lock().unwrap().rekey(NOW - 1000, 4);
    let root = {
        let w = t.0.lock().unwrap();
        humid_pq2::DualVerifyingKey::from_bytes(&w.root.verifying_key().to_bytes()).unwrap()
    };
    let mut restarted = Link::new(Unit::Core, root, policy_of, t.clone(), Box::new(|| NOW));
    restarted.set_policy_floor(floor);
    assert_eq!(
        block_on(restarted.connect()),
        Err(LinkError::PolicyRollback)
    );
    // and the same link, fetching again past its certificate's half life
    link.forget();
    t.0.lock().unwrap().now = NOW + DAY / 2 + 1;
    assert_eq!(block_on(link.connect()), Err(LinkError::PolicyRollback));
}
