// The kernel's public surface for the first paint (Welcome, Lock, the Vault and the shell).
// Screens import from here or from core/setup.js and nowhere else in core/ (tests/ia.test.js
// checks), so what the app can do is two lists. Setting up, joining, recovery and helping
// others are in core/setup.js, which loads with the screens that need it, so its code and
// @humid/recovery and @humid/pass stay out of the first paint (startEnroll/startJoin below
// fetch it on the first tap).
export { toast, friendly, cancelled, buzz } from "./notify.js";
export { holdComplete, holdCancel, gateLabel } from "./interrupt.js";
export { boot, connectServer, retryConnection, serverPinned, markPicking, setPref, unlock, reconnect, lock, lockNow, resetSimulation } from "./session.js";
export { refresh, addDocument, warmSeal, addIdRecord, addCardRecord, readCardTap, readCardPhoto, checkPass, addPass, openItem, closeViewer, saveCopy, exportSealed, setPinned, setDecoy, setDecoys, renameItem, deleteItem, itemById, ID_TYPE, CARD_TYPE, PASS_TYPE } from "./vault.js";
export { loadLedger, checkContinuity } from "./ledger.js";
export { loadDevices, findLink, approveLink, removeDevice } from "./devices.js";
export { saveDuress, loadDuress, setWitnessAlert, clearLockdown, checkinArmed, checkinOffered, loadCheckin, armCheckin, checkIn, disarmCheckin, clockOffset } from "./safety.js";
export { readChip, dismissChipRead, chipReader, readChipInto } from "./chips.js";
export { eraseEverything, resetLocal } from "./account.js";
export { loadAlerts, cancelRecovery, forgetNewCard, resumeNewCard } from "./alerts.js";
export { startEnroll, startJoin } from "./starts.js";
export { setDraft, clearDraft, takeDraft, current as draft, kept as keptDraft, CARD_DRAFT } from "./drafts.js";
export { comms, MESSAGE_KINDS } from "./comms/contract.js";
// 4.0 person to person: the Messages screens import core/messaging.js directly (a leaf, loaded
// with their chunk), so the protocol code is never in the first paint.
// The duress gestures: one recognizer for the Lock screen and Practice (APP-01).
export { createTapCounter, createHoldTimer, isDuressHold, describeTaps, seconds, TAP_WINDOW_MS, DURESS_HOLD_MS } from "./gesture.js";
