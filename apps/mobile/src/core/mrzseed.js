// Reading a still's MRZ after the live loop already has a valid, not yet confirmed, reading
// (screens/add/camera.jsx readStill, seed): the live reads vote with the still's, and the still's
// own reading has to be valid and the same as what the vote settled on. Otherwise the vote
// could be carried by earlier frames alone and the stored page never checked.

/** r: what MrzConsensus.add() returned for the still's reading. seeded: the vote includes the live reads. */
export const confirmedByStill = (r, seeded) =>
  !!r.stable && (!seeded || (!!r.best?.valid && !!r.result && r.best.lines.join("/") === r.result.lines.join("/")));
