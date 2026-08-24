# Examples

This crate includes several runnable examples demonstrating how to interact with AX.25 TNCs, send and receive frames, build simple applications, and experiment with packet radio.

Each example is invoked with:

```
cargo run --example <name> -- <arguments>
```

---

## **listen.rs**

Listen for incoming AX.25 frames from a TNC and print timestamps + decoded frames to stdout.

**Usage:**

```
cargo run --example listen -- <tnc-address>
```

---

## **send.rs**

Transmit a single Unnumbered Information (UI) frame containing a text message.

**Usage:**

```
cargo run --example send -- <tnc-address> <source-callsign> <dest-callsign> <message>
```

---

## **time.rs**

Broadcast the current UTC time periodically and respond immediately to incoming time‑request frames.

**Usage:**

```
cargo run --example time -- <tnc-address> <my-callsign>
```

---

## **chat.rs**

Interactive over‑the‑air chat: listens for incoming UI frames while reading stdin to send outgoing messages.

**Usage:**

```
cargo run --example chat -- <tnc-address> <my-callsign> <dest-callsign>
```

---

## **logger.rs**

Log all incoming frames to stdout in a tabular format including timestamps, source, destination, and payload.

**Usage:**

```
cargo run --example logger -- <tnc-address>
```

---

## **aprs_beacon.rs**

Transmit APRS position reports via UI frames at a fixed interval.

**Usage:**

```
cargo run --example aprs_beacon -- <tnc-address> <callsign> <dest-callsign> <comment> <interval-seconds>
```

---

## **repeater.rs**

Operate as an AX.25 digipeater: listen for incoming UI frames and retransmit them if your callsign appears in the route path.

**Usage:**

```
cargo run --example repeater -- <tnc-address> <my-callsign>
```

---

## **filter.rs**

Filter incoming traffic: print only frames whose source or destination matches a target callsign.

**Usage:**

```
cargo run --example filter -- <tnc-address> <target-callsign>
```

---

## **file_transfer.rs**

Transmit larger text payloads by splitting them into sequential AX.25 UI frames.

**Usage:**

```
cargo run --example file_transfer -- <tnc-address> <source-callsign> <dest-callsign> <message-string>
```
