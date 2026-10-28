// Fixed synthetic payload only. Never substitute user-controlled HTML or JavaScript.
export const labScript =
  "document.getElementById('lab-proof').textContent='Harmless script executed inside the isolated lab.';";
export const labScriptHash =
  "sha256-2ZycNe7hqWB32NZzQF7/BPbdPbDviPxKgaAJJWJ0DRk=";
export const labPayload = `<script>${labScript}</script>`;
export const labDocument = `<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src '${labScriptHash}'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"><style>body{color:#b5ef9e;background:#151b17;font:13px/1.6 system-ui;padding:10px}</style><p id="lab-proof">No script has executed.</p>${labPayload}`;
