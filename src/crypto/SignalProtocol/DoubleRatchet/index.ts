/**
 * Signal Protocol Double Ratchet Index
 * Exports all Double Ratchet functions
 * @module SignalProtocol/DoubleRatchet
 */

export {
  initializeDoubleRatchet,
  encryptMessage,
  decryptMessage,
  performDHRatchetStep,
} from "./DoubleRatchet";

export type { DoubleRatchetState, MessageKeys } from "./types";
