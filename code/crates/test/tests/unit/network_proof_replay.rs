//! WHARFEDALE: the network actor replays the validator proofs of connected peers to a
//! late subscriber, as it does listen addresses, peers and subscriptions. A peer sends
//! its proof once per session, right after connecting, which can be before consensus
//! subscribes; without the replay that proof was lost until the peer reconnected.
//!
//! Two real network actors on localhost: `validator` holds a proof, `observer` dials it.

use std::time::Duration;

use async_trait::async_trait;
use libp2p_identity::Keypair;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use rand::{rngs::StdRng, SeedableRng};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Instant};

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::{Ed25519Signer, TestContext};

use malachitebft_app::spawn::spawn_network_actor;
use malachitebft_codec::Codec;
use malachitebft_config::{ConsensusConfig, TransportProtocol, ValueSyncConfig};
use malachitebft_engine::network::{
    Msg as NetworkMsg, NetworkEvent, NetworkIdentity, NetworkRef, PersistentPeersOp,
};
use malachitebft_metrics::SharedRegistry;
use malachitebft_signing::Signer;
use malachitebft_signing_ed25519::PrivateKey;

type Event = NetworkEvent<TestContext>;

/// Forwards every network event it receives to a channel.
struct Probe;

#[async_trait]
impl Actor for Probe {
    type Msg = Event;
    type State = mpsc::UnboundedSender<Event>;
    type Arguments = mpsc::UnboundedSender<Event>;

    async fn pre_start(
        &self,
        _myself: ActorRef<Event>,
        tx: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(tx)
    }

    async fn handle(
        &self,
        _myself: ActorRef<Event>,
        event: Event,
        tx: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let _ = tx.send(event);
        Ok(())
    }
}

async fn subscribe(network: &NetworkRef<TestContext>) -> mpsc::UnboundedReceiver<Event> {
    let (tx, rx) = mpsc::unbounded_channel();
    let (probe, _) = Actor::spawn(None, Probe, tx).await.unwrap();
    network
        .cast(NetworkMsg::Subscribe(Box::new(probe)))
        .unwrap();
    rx
}

/// The first event `pick` accepts within `within`, or `None`.
async fn next_matching<T>(
    rx: &mut mpsc::UnboundedReceiver<Event>,
    within: Duration,
    mut pick: impl FnMut(Event) -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + within;
    loop {
        let event = timeout(
            deadline.saturating_duration_since(Instant::now()),
            rx.recv(),
        )
        .await
        .ok()??;
        if let Some(t) = pick(event) {
            return Some(t);
        }
    }
}

fn proof_from(public_key: &[u8]) -> impl FnMut(Event) -> Option<()> + '_ {
    move |event| match event {
        NetworkEvent::ValidatorProofReceived { proof, .. } if proof.public_key == public_key => {
            Some(())
        }
        _ => None,
    }
}

async fn spawn_node(moniker: &str, identity: NetworkIdentity) -> NetworkRef<TestContext> {
    let mut cfg = ConsensusConfig::default();
    cfg.p2p.listen_addr = TransportProtocol::Quic.multiaddr("127.0.0.1", 0);
    cfg.p2p.discovery.enabled = false;
    let registry = SharedRegistry::global().with_moniker(moniker.to_string());
    spawn_network_actor::<TestContext, _>(
        &cfg,
        &ValueSyncConfig::default(),
        identity,
        &registry,
        ProtobufCodec,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_late_subscriber_gets_the_proofs_of_connected_peers() {
    // The validator: a network identity carrying a signed proof for its consensus key.
    let private_key = PrivateKey::generate(StdRng::seed_from_u64(7));
    let public_key = private_key.public_key().as_bytes().to_vec();
    let keypair = Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id().to_bytes();
    let proof = Ed25519Signer::new(private_key)
        .sign_validator_proof(public_key.clone(), peer_id)
        .await
        .unwrap();
    let proof_bytes = Codec::encode(&ProtobufCodec, &proof).unwrap();
    let validator = spawn_node(
        "validator",
        NetworkIdentity::new_validator("validator".into(), keypair, "v".into(), proof_bytes),
    )
    .await;

    let mut on_validator = subscribe(&validator).await;
    let addr = next_matching(&mut on_validator, Duration::from_secs(10), |e| match e {
        NetworkEvent::Listening(addr) => Some(addr),
        _ => None,
    })
    .await
    .expect("the validator listens");

    // The observer dials it, with one subscriber already in place.
    let observer = spawn_node(
        "observer",
        NetworkIdentity::new("observer".into(), Keypair::generate_ed25519(), None),
    )
    .await;
    let mut early = subscribe(&observer).await;
    ractor::call!(
        observer,
        NetworkMsg::UpdatePersistentPeers,
        PersistentPeersOp::Add(addr)
    )
    .unwrap()
    .unwrap();

    next_matching(&mut early, Duration::from_secs(20), proof_from(&public_key))
        .await
        .expect("the proof reaches the subscriber present when it arrives");

    // A subscriber that comes after the proof still gets it.
    let mut late = subscribe(&observer).await;
    next_matching(&mut late, Duration::from_secs(5), proof_from(&public_key))
        .await
        .expect("the proof is replayed to a late subscriber");

    // Once the validator is gone, its proof is not replayed any more.
    validator.stop(None);
    next_matching(&mut early, Duration::from_secs(20), |e| {
        matches!(e, NetworkEvent::PeerDisconnected(_)).then_some(())
    })
    .await
    .expect("the observer sees the validator disconnect");
    let mut after = subscribe(&observer).await;
    sleep(Duration::from_millis(500)).await;
    assert!(
        next_matching(
            &mut after,
            Duration::from_millis(1),
            proof_from(&public_key)
        )
        .await
        .is_none(),
        "a disconnected peer's proof is dropped"
    );

    observer.stop(None);
}
