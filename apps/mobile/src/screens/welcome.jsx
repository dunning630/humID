// Welcome: what HumID is, in one screen. Then Create my HumID, or I already have one.
import { Mark, Wordmark } from "../brand/mark.jsx";
import { Icon } from "../brand/icons.jsx";
import { Row, HowProtectedLink } from "../ui/kit.jsx";
import { checkPromise } from "../ui/labels.js";
import { startEnroll, startJoin } from "../core/index.js";

export function Welcome() {
  return (
    <main class="screen">
      <div class="hero" style={{ paddingTop: "4vh" }}>
        <Mark size={168} label="HumID" />
        <Wordmark height={34} />
        <p class="lede">Your documents, opened only by a live face or fingerprint check. No password exists.</p>
      </div>
      <div class="rows">
        <Row icon="fingerprint" tone="amber" chevron={false} title="A live check is the only key" sub={checkPromise()} />
        <Row icon="lock" tone="mint" chevron={false} title="Sealed on your phone" sub="Documents are encrypted here before they leave. Your vault can't read them, or even their names." />
        <Row icon="chain" tone="mint" chevron={false} title="Every access on the record" sub="A tamper-evident log your phone verifies for itself." />
        <Row icon="user" tone="mint" chevron={false} title="No name, no email, no number" sub="Your HumID is a set of keys. Even paying for it doesn't tell anyone who you are." />
      </div>
      <div class="foot stack">
        <button class="btn primary lg block" onClick={startEnroll}><Icon name="fingerprint" />Create my HumID</button>
        <button class="btn quiet block" onClick={startJoin}><Icon name="key" />I already have HumID</button>
        <p class="fine center">Post-quantum encryption, sealed on your phone before it goes anywhere. <HowProtectedLink class="link muted" /></p>
      </div>
    </main>
  );
}
