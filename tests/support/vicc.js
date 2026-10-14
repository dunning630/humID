// Puts a simulated chip into a real PC/SC stack: connects to vpcd (the
// vsmartcard virtual reader driver for pcscd) and answers its requests.
// Protocol: 2-byte big-endian length, then either a 1-byte control code
// (0 power off, 1 power on, 2 reset, 4 get ATR) or a command APDU.
import net from "node:net";

const ATR = Uint8Array.of(0x3b, 0x80, 0x80, 0x01, 0x01); // contactless, T=1, no historical bytes

export function insertCard(chip, { host = "127.0.0.1", port = 35963 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, host);
    let buf = Buffer.alloc(0);
    let queue = Promise.resolve();
    const send = (b) => { const h = Buffer.alloc(2); h.writeUInt16BE(b.length); sock.write(Buffer.concat([h, Buffer.from(b)])); };
    sock.on("connect", () => resolve({ remove: () => new Promise((r) => { sock.end(); sock.once("close", r); }) }));
    sock.on("error", reject);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const n = buf.readUInt16BE(0);
        const msg = buf.subarray(2, 2 + n);
        buf = buf.subarray(2 + n);
        if (n === 1) { if (msg[0] === 4) send(ATR); continue; }
        const apdu = Uint8Array.from(msg);
        queue = queue.then(async () => send(await chip.transceive(apdu)));
      }
    });
  });
}
