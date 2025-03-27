import { Injectable } from '@angular/core';
import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

@Injectable({
  providedIn: 'root'
})
export class CryptoService {
  private crypto = window.crypto;

  // Store keys for ECDH web crypto
  private myKeyPair: {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    privateKeyRaw?: ArrayBuffer;
    publicKeyRaw?: ArrayBuffer;
  } | null = null;

  // Store keys for Ed25519 using TweetNaCl
  private signingKeyPair: {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
  } | null = null;

  // Maps to store keys for each user
  private sharedSecrets: Map<string, CryptoKey> = new Map();
  private encryptionKeys: Map<string, CryptoKey> = new Map();
  private hmacKeys: Map<string, CryptoKey> = new Map();
  private signingPublicKeys: Map<string, Uint8Array> = new Map();

  constructor() { }


  async initializeKeys(): Promise<{ publicKey: string; signingPublicKey: string }> {
    // Generate ECDH key pair using Web Crypto
    const ecdhKeyPair = await this.generateECDHKeyPair();

    // Generate Ed25519 key pair using TweetNaCl
    const signingKeyPair = this.generateSigningKeyPair();

    return {
      publicKey: ecdhKeyPair.publicKey,
      signingPublicKey: signingKeyPair.publicKey
    };
  }

  // Generate ECDH key pair using Web Crypto
  private async generateECDHKeyPair(): Promise<{ publicKey: string }> {
    try {
      // Generate ECDH key pair
      this.myKeyPair = await this.crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
      ) as { privateKey: CryptoKey; publicKey: CryptoKey };

      // Export public key to share with other party
      const publicKeyRaw = await this.crypto.subtle.exportKey(
        'spki',
        this.myKeyPair.publicKey
      );
      this.myKeyPair.publicKeyRaw = publicKeyRaw;

      return {
        publicKey: this.arrayBufferToBase64(publicKeyRaw)
      };
    } catch (error) {
      console.error('Error generating ECDH key pair:', error);
      throw error;
    }
  }

  // Generate Ed25519 key pair using TweetNaCl
  private generateSigningKeyPair(): { publicKey: string } {
    try {
      // Generate Ed25519 key pair
      const keyPair = nacl.sign.keyPair();

      this.signingKeyPair = {
        privateKey: keyPair.secretKey,
        publicKey: keyPair.publicKey
      };

      console.log('Ed25519 key pair generated with TweetNaCl');


      return {
        publicKey: util.encodeBase64(this.signingKeyPair.publicKey)
      };
    } catch (error) {
      console.error('Error generating Ed25519 key pair:', error);
      throw error;
    }
  }

  // Store public key for a user
  storeSigningPublicKey(username: string, publicKeyBase64: string): void {
    try {
      const publicKey = util.decodeBase64(publicKeyBase64);
      this.signingPublicKeys.set(username, publicKey);
      console.log(`Stored Ed25519 public key for ${username}`);
    } catch (error) {
      console.error(`Error storing signing public key for ${username}:`, error);
      throw error;
    }
  }

  // Compute shared secret with another user
  async computeSharedSecret(otherPublicKeyBase64: string, username: string): Promise<void> {
    try {
      if (!this.myKeyPair) {
        throw new Error('Local key pair not initialized');
      }

      // Import other's public key
      const otherPublicKeyRaw = this.base64ToArrayBuffer(otherPublicKeyBase64);
      const otherPublicKey = await this.crypto.subtle.importKey(
        'spki',
        otherPublicKeyRaw,
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        false,
        []
      );

      // Derive shared secret
      const sharedSecret = await this.crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: otherPublicKey,
        },
        this.myKeyPair.privateKey,
        256
      );

      // Import the shared secret
      const baseKey = await this.crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'HKDF' },
        false,
        ['deriveKey']
      );

      // Derive AES key for encryption
      const aesKey = await this.crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(16),
          info: new TextEncoder().encode('AES-GCM-Encryption'),
        },
        baseKey,
        {
          name: 'AES-GCM',
          length: 256,
        },
        false,
        ['encrypt', 'decrypt']
      );

      // Derive HMAC key
      const hmacKey = await this.crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(16),
          info: new TextEncoder().encode('HMAC-Authentication'),
        },
        baseKey,
        {
          name: 'HMAC',
          hash: 'SHA-256',
        },
        false,
        ['sign', 'verify']
      );

      // Store keys for this user
      this.sharedSecrets.set(username, baseKey);
      this.encryptionKeys.set(username, aesKey);
      this.hmacKeys.set(username, hmacKey);

      console.log(`Shared secret established with ${username}`);
    } catch (error) {
      console.error('Error computing shared secret:', error);
      throw error;
    }
  }

  // Encrypt a message
  async encryptMessage(message: string, username: string): Promise<{
    encryptedMessage: string;
    hmac: string;
    signature: string;
  }> {
    try {
      // Get encryption key for this user
      const encryptionKey = this.encryptionKeys.get(username);
      const hmacKey = this.hmacKeys.get(username);

      if (!encryptionKey || !hmacKey || !this.signingKeyPair) {
        throw new Error('Keys not initialized for this user');
      }

      // Log what we're using
      console.log('Using TweetNaCl.js for Ed25519 signatures');

      // Generate random IV
      const iv = this.crypto.getRandomValues(new Uint8Array(12));
      const encodedMessage = new TextEncoder().encode(message);

      // Encrypt the message
      const encryptedData = await this.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        encryptionKey,
        encodedMessage
      );

      // Combine IV and encrypted data
      const encryptedMessage = new Uint8Array(iv.length + encryptedData.byteLength);
      encryptedMessage.set(iv);
      encryptedMessage.set(new Uint8Array(encryptedData), iv.length);

      // Generate HMAC for message authentication using Web Crypto
      const hmac = await this.crypto.subtle.sign(
        {
          name: 'HMAC',
        },
        hmacKey,
        encryptedMessage
      );

      // Sign the message with Ed25519 using TweetNaCl
      const signature = nacl.sign.detached(encryptedMessage, this.signingKeyPair.privateKey);
      console.log('Ed25519 signature generated');

      return {
        encryptedMessage: this.arrayBufferToBase64(encryptedMessage),
        hmac: this.arrayBufferToBase64(hmac),
        signature: util.encodeBase64(signature)
      };
    } catch (error) {
      console.error('Error encrypting message:', error);
      throw error;
    }
  }

  // Decrypt a message from a specific user
  async decryptMessage(
    encryptedMessageBase64: string,
    hmacBase64: string,
    signatureBase64: string,
    senderUsername: string
  ): Promise<{ isValid: boolean; message: string }> {
    try {
      // Get encryption key for this user
      const encryptionKey = this.encryptionKeys.get(senderUsername);
      const hmacKey = this.hmacKeys.get(senderUsername);
      const signingPublicKey = this.signingPublicKeys.get(senderUsername);

      if (!encryptionKey || !hmacKey || !signingPublicKey) {
        console.error(`Missing keys for ${senderUsername}`);
        return { isValid: false, message: 'Keys not established for this user' };
      }

      // Convert from Base64
      const encryptedMessage = new Uint8Array(this.base64ToArrayBuffer(encryptedMessageBase64));
      const receivedHmac = this.base64ToArrayBuffer(hmacBase64);
      const signature = util.decodeBase64(signatureBase64);

      console.log('Verifying Ed25519 signature with TweetNaCl');



      // Verify Ed25519 signature using TweetNaCl
      const isSignatureValid = nacl.sign.detached.verify(
        encryptedMessage,
        signature,
        signingPublicKey
      );

      if (!isSignatureValid) {
        console.error('Ed25519 signature verification failed');
        return { isValid: false, message: 'Signature verification failed' };
      }

      // Verify HMAC using Web Crypto
      const isHmacValid = await this.crypto.subtle.verify(
        {
          name: 'HMAC',
        },
        hmacKey,
        receivedHmac,
        encryptedMessage
      );

      if (!isHmacValid) {
        console.error('HMAC verification failed');
        return { isValid: false, message: 'Message authentication failed' };
      }

      // Extract IV (first 12 bytes)
      const iv = encryptedMessage.slice(0, 12);
      const ciphertext = encryptedMessage.slice(12);

      // Decrypt the message
      const decryptedData = await this.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv,
        },
        encryptionKey,
        ciphertext
      );

      // Decode message
      const decoder = new TextDecoder();
      const decryptedMessage = decoder.decode(decryptedData);

      return {
        isValid: true,
        message: decryptedMessage,
      };
    } catch (error: unknown) {
      console.error('Error decrypting message:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return { isValid: false, message: 'Decryption error: ' + errorMessage };
    }
  }

  // Helper functions for base64 conversion
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
