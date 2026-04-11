'use strict';

class WebAuthnError extends Error {
  constructor(message, originalError = null) {
    super(message);
    this.name = 'WebAuthnError';
    this.originalError = originalError;
  }
}

/**
 * Safely convert base64url string to ArrayBuffer, handling malformed inputs
 * and missing padding intrinsically.
 * 
 * @param {string} b64u
 * @returns {ArrayBuffer}
 */
function base64urlToArrayBuffer(b64u) {
  if (typeof b64u !== 'string') {
    throw new WebAuthnError(`Expected base64url string, received ${typeof b64u}`);
  }
  
  try {
    const base64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padLen);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (err) {
    throw new WebAuthnError('Failed to parse base64url string into ArrayBuffer.', err);
  }
}

/**
 * Convert ArrayBuffer to strictly-compliant base64url string.
 * 
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToBase64url(buffer) {
  if (!(buffer instanceof ArrayBuffer) && !ArrayBuffer.isView(buffer)) {
    throw new WebAuthnError('Expected ArrayBuffer or typed array for encoding.');
  }

  try {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    // Process in chunks to avoid stack overflow for large buffers
    const chunkSize = 0x8000; 
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  } catch (err) {
    throw new WebAuthnError('Failed to encode ArrayBuffer into base64url.', err);
  }
}

/**
 * Wrapper for navigator.credentials.create
 * Parses a standard WebAuthn challenge from the server and handles hardware boundaries.
 * 
 * @param {object} createOptions 
 * @param {AbortSignal} [signal] Optional abort signal from AbortController
 * @returns {Promise<object>}
 */
async function registerPasskey(createOptions, signal = null) {
  if (typeof window === 'undefined' || !window.isSecureContext) {
    throw new WebAuthnError('WebAuthn requires a secure context (HTTPS or localhost).');
  }
  if (!navigator.credentials || !navigator.credentials.create) {
    throw new WebAuthnError('WebAuthn is not supported in this browser environment.');
  }

  try {
    const publicKey = { ...createOptions.publicKey };
    
    // Convert required challenge and user.id securely
    if (publicKey.challenge) publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
    if (publicKey.user?.id) publicKey.user.id = base64urlToArrayBuffer(publicKey.user.id);
    
    if (Array.isArray(publicKey.excludeCredentials)) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(cred => ({
        ...cred,
        id: base64urlToArrayBuffer(cred.id)
      }));
    }

    const payload = { publicKey };
    if (signal) payload.signal = signal;

    const credential = await navigator.credentials.create(payload);

    if (!credential) {
      throw new WebAuthnError('Hardware prompt was aborted or returned null credential.');
    }

    return {
      id: credential.id,
      rawId: arrayBufferToBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      response: {
        clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
        transports: typeof credential.response.getTransports === 'function' 
          ? credential.response.getTransports() 
          : []
      },
      clientExtensionResults: typeof credential.getClientExtensionResults === 'function' 
        ? credential.getClientExtensionResults() 
        : {}
    };
  } catch (err) {
    if (err.name === 'AbortError') throw new WebAuthnError('Passkey registration was actively aborted.', err);
    if (err.name === 'NotAllowedError') throw new WebAuthnError('Hardware prompt dismissed or explicitly denied by the user.', err);
    throw new WebAuthnError('Unexpected error during hardware attestation phase.', err);
  }
}

/**
 * Wrapper for navigator.credentials.get
 * Parses a standard WebAuthn challenge from the server, managing dynamic allowCredentials
 * and strict parsing of the physical assertion signatures.
 * 
 * @param {object} requestOptions 
 * @param {AbortSignal} [signal] Optional abort signal
 * @returns {Promise<object>}
 */
async function loginWithPasskey(requestOptions, signal = null) {
  if (typeof window === 'undefined' || !window.isSecureContext) {
    throw new WebAuthnError('WebAuthn requires a secure context (HTTPS or localhost).');
  }
  if (!navigator.credentials || !navigator.credentials.get) {
    throw new WebAuthnError('WebAuthn is not supported in this browser environment.');
  }

  try {
    const publicKey = { ...requestOptions.publicKey };

    if (publicKey.challenge) publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
    
    if (Array.isArray(publicKey.allowCredentials)) {
      publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
        ...cred,
        id: base64urlToArrayBuffer(cred.id)
      }));
    }

    const payload = { publicKey };
    if (signal) payload.signal = signal;

    const assertion = await navigator.credentials.get(payload);

    if (!assertion) {
      throw new WebAuthnError('Hardware prompt was aborted or returned null assertion.');
    }

    return {
      id: assertion.id,
      rawId: arrayBufferToBase64url(assertion.rawId),
      type: assertion.type,
      authenticatorAttachment: assertion.authenticatorAttachment || null,
      response: {
        authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
        clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
        signature: arrayBufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null
      },
      clientExtensionResults: typeof assertion.getClientExtensionResults === 'function' 
        ? assertion.getClientExtensionResults() 
        : {}
    };
  } catch (err) {
    if (err.name === 'AbortError') throw new WebAuthnError('Passkey login was actively aborted.', err);
    if (err.name === 'NotAllowedError') throw new WebAuthnError('Hardware prompt dismissed or explicitly denied by the user.', err);
    throw new WebAuthnError('Unexpected error during physical assertion verification.', err);
  }
}

module.exports = {
  WebAuthnError,
  registerPasskey,
  loginWithPasskey,
  base64urlToArrayBuffer,
  arrayBufferToBase64url
};
