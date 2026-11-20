import { useCallback, useEffect, useState } from "react";
import { api, reason } from "../lib/api";
import type {
  DeviceEncryption,
  DeviceFacts as Facts,
  DeviceRemoteDesktop,
  DeviceSecureBoot,
  DeviceTpm,
} from "../lib/types";

/**
 * This device: facts Windows already holds about this PC, in one place.
 *
 * Each is said with where it came from. There is no score, no count of
 * checks passed and no "secure": what these are worth is the reader's to
 * weigh. A fact that could not be read says so and why, never "none". And
 * nothing here changes a setting.
 */

/** Ends a reason that may or may not have its own full stop. */
function stop(text: string): string {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

function secureBoot(fact: DeviceSecureBoot): string[] {
  const lines = [`Secure Boot is ${fact.on ? "on" : "off"}, according to Windows.`];
  const move = "the update of its Secure Boot certificates to Microsoft's 2023 ones";
  switch (fact.certificates) {
    case null:
      lines.push(`Windows reports nothing about ${move}.`);
      break;
    case "Updated":
      lines.push("Windows reports its Secure Boot certificates as updated to Microsoft's 2023 ones.");
      break;
    case "InProgress":
      lines.push(`Windows reports ${move} as in progress.`);
      break;
    case "NotStarted":
      lines.push(`Windows reports ${move} as not started.`);
      break;
    default:
      lines.push(`Windows reports ${move} as "${fact.certificates}".`);
  }
  if (fact.certificate_error !== null) {
    lines.push(
      `It recorded an error while doing so (0x${fact.certificate_error
        .toString(16)
        .toUpperCase()
        .padStart(8, "0")}).`,
    );
  }
  return lines;
}

function tpm(fact: DeviceTpm): string {
  const source = fact.source === "provider" ? "Windows' TPM provider" : "tpmtool";
  if (!fact.present) return "tpmtool reports no TPM on this PC.";
  const readiness = fact.source === "provider" ? "for use" : "for storage";
  const ready =
    fact.ready === true
      ? `, ready ${readiness}`
      : fact.ready === false
        ? `, not ready ${readiness}`
        : "";
  const version = fact.version ? `, version ${fact.version}` : "";
  const unsaid = fact.ready === null ? " Whether it is ready was not said." : "";
  return `This PC has a TPM${version}${ready}, according to ${source}.${unsaid}`;
}

function encryption(fact: DeviceEncryption): string {
  const source =
    fact.source === "provider" ? "Windows' drive encryption provider" : "Explorer";
  const drive = `Drive ${fact.drive}`;
  if (fact.conversion === "decrypted") {
    return `${drive} is not encrypted, according to ${source}.`;
  }
  const state =
    fact.conversion === "encrypted"
      ? "is encrypted"
      : fact.conversion === "encrypting"
        ? "is being encrypted"
        : fact.conversion === "decrypting"
          ? "is being decrypted"
          : fact.conversion === "encryption_paused"
            ? "is partly encrypted, with encryption paused"
            : fact.conversion === "decryption_paused"
              ? "is partly decrypted, with decryption paused"
              : null;
  const protection =
    fact.protection === true
      ? "its protection is on"
      : fact.protection === false
        ? "its protection is off"
        : "whether its protection is on is not known";
  return state === null
    ? `For drive ${fact.drive}, ${protection}, according to ${source}. How far it is encrypted was not said.`
    : `${drive} ${state} and ${protection}, according to ${source}.`;
}

function remoteDesktop(fact: DeviceRemoteDesktop): string {
  const switched = `Remote Desktop is switched ${fact.on ? "on" : "off"}${
    fact.by_policy ? " by a policy" : ""
  }, according to Windows' settings`;
  const port =
    fact.port !== null
      ? `its port (${fact.port})`
      : "3389, its usual port, as Windows records none";
  if (fact.listening.state === "unread") {
    return `${switched}. Whether anything is listening on ${port} could not be read: ${stop(fact.listening.why)}`;
  }
  return `${switched}, and ${fact.listening.value ? "something is" : "nothing is"} listening on ${port}.`;
}

export default function DeviceFacts() {
  const [facts, setFacts] = useState<Facts | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);

  const refresh = useCallback(async () => {
    setReading(true);
    try {
      setFacts(await api.deviceFacts());
      setError(null);
    } catch (cause) {
      setFacts(null);
      setError(reason(cause));
    } finally {
      setReading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <>
      <p className="modal-label">This device</p>
      {error && (
        <div className="notice notice-warn">
          <strong>Facts about this device could not be read.</strong> {error}
        </div>
      )}
      {facts === null && !error && <p className="muted">Reading what Windows knows about this PC.</p>}
      {facts && (
        <ul className="entries compact">
          <li className="entry">
            <div className="entry-body">
              {facts.secure_boot.state === "read" ? (
                secureBoot(facts.secure_boot.value).map((line, index) => (
                  <span key={line} className={index === 0 ? "action" : "detail"}>
                    {line}
                  </span>
                ))
              ) : (
                <span className="action">
                  Whether Secure Boot is on could not be read: {stop(facts.secure_boot.why)}
                </span>
              )}
              <span className="detail">
                Secure Boot lets the PC start only from software signed with keys it trusts.
              </span>
            </div>
          </li>

          <li className="entry">
            <div className="entry-body">
              {facts.tpm.state === "read" ? (
                <>
                  <span className="action">{tpm(facts.tpm.value)}</span>
                  {facts.tpm.value.instead_of && (
                    <span className="detail">
                      {stop(facts.tpm.value.instead_of)} So this is tpmtool's answer, run as
                      you.
                    </span>
                  )}
                </>
              ) : (
                <span className="action">
                  Whether this PC has a TPM could not be read: {stop(facts.tpm.why)}
                </span>
              )}
              <span className="detail">
                A TPM is a chip that holds keys, such as the one that unlocks an encrypted
                drive.
              </span>
            </div>
          </li>

          <li className="entry">
            <div className="entry-body">
              {facts.encryption.state === "read" ? (
                <>
                  <span className="action">{encryption(facts.encryption.value)}</span>
                  {facts.encryption.value.instead_of && (
                    <span className="detail">
                      {stop(facts.encryption.value.instead_of)} So this is what Explorer
                      shows, read as you.
                    </span>
                  )}
                </>
              ) : (
                <span className="action">
                  Whether drive C: is encrypted could not be read: {stop(facts.encryption.why)}
                </span>
              )}
              <span className="detail">
                While its protection is on, an encrypted drive cannot be read if it is taken
                out of this PC.
              </span>
            </div>
          </li>

          <li className="entry">
            <div className="entry-body">
              <span className="action">
                {facts.remote_desktop.state === "read"
                  ? remoteDesktop(facts.remote_desktop.value)
                  : `Whether Remote Desktop is on could not be read: ${stop(facts.remote_desktop.why)}`}
              </span>
              <span className="detail">
                Remote Desktop lets another computer sign in to this one over the network.
              </span>
            </div>
          </li>
        </ul>
      )}
      <button className="link-button" onClick={() => void refresh()} disabled={reading}>
        {reading ? "Reading…" : "Read these again"}
      </button>
    </>
  );
}
