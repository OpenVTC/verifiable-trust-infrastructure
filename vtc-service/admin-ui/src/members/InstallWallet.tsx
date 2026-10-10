// How to install the VTA Wallet browser extension by hand.
//
// The extension is not in a browser store yet, so a member side-loads it from
// source. These steps track the plugin's own README
// (github.com/OpenVTC/vta-browser-plugin, "Installing the extension into your
// browser") — change them together.

export const PLUGIN_REPO = "https://github.com/OpenVTC/vta-browser-plugin";

const BUILD_COMMANDS = [
  "git clone https://github.com/OpenVTC/vta-browser-plugin.git",
  "cd vta-browser-plugin",
  "npm install",
  "npm run build",
].join("\n");

export function InstallWallet({ open }: { open: boolean }) {
  return (
    <details className="install" open={open}>
      <summary>
        <span>Install the VTA Wallet browser extension</span>
        <span className="install-hint">about 5 minutes, one time</span>
      </summary>

      <div className="install-body">
        <p>
          The wallet connects this browser to your own Verifiable Trust Agent,
          so your VTA can sign you in here as your member identity — no
          password, and the key stays in your VTA. It isn't in a browser store yet,
          so install it by hand from{" "}
          <a href={PLUGIN_REPO} target="_blank" rel="noopener noreferrer">
            OpenVTC/vta-browser-plugin
          </a>{" "}
          on GitHub. It works in Chrome, Edge, Brave and Arc.
        </p>

        <ol className="steps">
          <li>
            <h4>Build it</h4>
            <p>
              You need <a href="https://nodejs.org" target="_blank" rel="noopener noreferrer">Node.js</a>{" "}
              24 or newer and <code>git</code>.
            </p>
            <pre>
              <code>{BUILD_COMMANDS}</code>
            </pre>
            <p className="muted">
              This produces a complete extension in{" "}
              <code>packages/extension/dist/</code>.
            </p>
          </li>
          <li>
            <h4>Load it into your browser</h4>
            <p>
              Open <code>chrome://extensions</code> (or{" "}
              <code>edge://extensions</code>, <code>brave://extensions</code>,{" "}
              <code>arc://extensions</code>), switch on{" "}
              <strong>Developer mode</strong>, click{" "}
              <strong>Load unpacked</strong> and choose the{" "}
              <code>packages/extension/dist/</code> folder.
            </p>
          </li>
          <li>
            <h4>Pin it and finish setup</h4>
            <p>
              Pin <strong>VTA Wallet</strong> to the toolbar. Setup opens on its
              own: enter your agent's address (a name like{" "}
              <code>webvh.example.com/@you</code> or a full{" "}
              <code>did:webvh:…</code>), then set the passkey lock. Work through
              it top to bottom — the order matters.
            </p>
          </li>
          <li>
            <h4>Come back and sign in</h4>
            <p>
              Reload this page. <strong>Sign in with your VTA</strong> becomes
              available. The first time, the wallet asks which of your VTA's
              identities this community knows you as and remembers the answer —
              choose the one you joined with.
            </p>
          </li>
        </ol>

        <p className="muted">
          New to all of this?{" "}
          <a href="https://openvtc.net" target="_blank" rel="noopener noreferrer">
            openvtc.net
          </a>{" "}
          explains what a Verifiable Trust Agent is and how to get one.
        </p>
      </div>
    </details>
  );
}
