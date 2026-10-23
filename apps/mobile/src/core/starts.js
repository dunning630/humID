// Welcome's two buttons. Setting up and joining are a chunk of their own (core/setup.js), so
// the first tap fetches it; the screen it opens shows the calm loading mark meanwhile.
export const startEnroll = () => import("./enroll.js").then((m) => m.startEnroll());
export const startJoin = () => import("./join.js").then((m) => m.startJoin());
