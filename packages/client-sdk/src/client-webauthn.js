'use strict';

/**
 * Convert base64url string to ArrayBuffer
 * @param {string} b64u
 * @returns {ArrayBuffer}
 */
function base64urlToArrayBuffer(b64u) {
  const base64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert ArrayBuffer to base64url string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Wrapper for navigator.credentials.create
 * Parses a standard WebAuthn challenge from the server
 * and returns the stringified hardware attestation.
 * 
 * @param {object} createOptions 
 * @returns {Promise<object>}
 */
async function registerPasskey(createOptions) {
  if (!navigator.credentials || !navigator.credentials.create) {
    throw new Error('WebAuthn is not supported in this browser.');
  }

  // Convert challenge string and user id to ArrayBuffer
  createOptions.publicKey.challenge = base64urlToArrayBuffer(createOptions.publicKey.challenge);
  createOptions.publicKey.user.id = base64urlToArrayBuffer(createOptions.publicKey.user.id);
  if (createOptions.publicKey.excludeCredentials) {
    for (const cred of createOptions.publicKey.excludeCredentials) {
      cred.id = base64urlToArrayBuffer(cred.id);
    }
  }

  const credential = await navigator.credentials.create(createOptions);

  return {
    id: credential.id,
    rawId: arrayBufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
      attestationObject: arrayBufferToBase64url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : []
    }
  };
}

/**
 * Wrapper for navigator.credentials.get
 * Parses a standard WebAuthn challenge from the server
 * and returns the stringified physical assertion.
 * 
 * @param {object} requestOptions 
 * @returns {Promise<object>}
 */
async function loginWithPasskey(requestOptions) {
  if (!navigator.credentials || !navigator.credentials.get) {
    throw new Error('WebAuthn is not supported in this browser.');
  }

  requestOptions.publicKey.challenge = base64urlToArrayBuffer(requestOptions.publicKey.challenge);
  if (requestOptions.publicKey.allowCredentials) {
    for (const cred of requestOptions.publicKey.allowCredentials) {
      cred.id = base64urlToArrayBuffer(cred.id);
    }
  }

  const assertion = await navigator.credentials.get(requestOptions);

  return {
    id: assertion.id,
    rawId: arrayBufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
      clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
      signature: arrayBufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null
    }
  };
}

module.exports = {
  registerPasskey,
  loginWithPasskey,
  base64urlToArrayBuffer,
  arrayBufferToBase64url
};
