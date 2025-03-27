import {Component, OnDestroy, OnInit} from '@angular/core';
import {FormsModule, ReactiveFormsModule} from '@angular/forms';
import {NgForOf, NgIf} from '@angular/common';
import {CryptoService} from '../../services/crypto.service';
import {SignalrService} from '../../services/signalr.service';

@Component({
  selector: 'app-chat',
  imports: [
    ReactiveFormsModule,
    NgIf,
    NgForOf,
    FormsModule
  ],
  templateUrl: './chat.component.html',
  styleUrl: './chat.component.css'
})
export class ChatComponent implements OnInit, OnDestroy {
  username = '';
  isConnected = false;
  connecting = false;
  userList: string[] = [];
  selectedUser: string | null = null;
  currentMessage = '';

  // Track which users have completed key exchange
  keyExchangeCompleted: Set<string> = new Set();

  // Store public keys of users
  publicKeys: Map<string, string> = new Map();
  signingPublicKeys: Map<string, string> = new Map();

  // Store messages
  messages: {
    from: string;
    to: string;
    text: string;
    isValid: boolean;
    timestamp: Date;
  }[] = [];

  constructor(
    private signalrService: SignalrService,
    private cryptoService: CryptoService
  ) { }

  async ngOnInit() {
    // Initialize SignalR service
    try {
      await this.signalrService.startConnection();

      // Register event handlers
      this.registerSignalRHandlers();
    } catch (error) {
      console.error('Failed to initialize SignalR connection:', error);
    }
  }

  ngOnDestroy() {
    this.signalrService.stopConnection();
  }

  private registerSignalRHandlers() {
    // Handle connection request
    this.signalrService.onRequestUserInfo(() => {

    });

    // Handle user list updates
    this.signalrService.onUserList((users: string[]) => {
      this.userList = users.filter(user => user !== this.username);
    });

    // Handle user disconnection
    this.signalrService.onUserDisconnected((username: string) => {
      this.userList = this.userList.filter(user => user !== username);
      this.publicKeys.delete(username);
      this.signingPublicKeys.delete(username);
      this.keyExchangeCompleted.delete(username);

      if (this.selectedUser === username) {
        this.selectedUser = null;
      }
    });

    // Handle incoming public keys
    this.signalrService.onPublicKey((username: string, publicKey: string) => {
      this.publicKeys.set(username, publicKey);

      // Compute shared secret when we receive a public key
      if (username !== this.username) {
        this.computeSharedSecret(username, publicKey);
      }
    });

    // Handle incoming signing public keys
    this.signalrService.onSigningPublicKey((username: string, publicKey: string) => {
      this.signingPublicKeys.set(username, publicKey);

      // Store the signing public key for verification - note no awaiting needed
      if (username !== this.username) {
        this.cryptoService.storeSigningPublicKey(username, publicKey);
      }
    });

    // Handle incoming messages
    this.signalrService.onReceiveMessage(
      async (sender: string, recipient: string, encryptedMsg: string, hmac: string, signature: string) => {
        // Only process messages for this user
        if (recipient !== this.username && sender !== this.username) {
          return;
        }

        // If this is a message sent by this user to someone else, just store it
        if (sender === this.username) {
          this.messages.push({
            from: sender,
            to: recipient,
            text: this.currentMessage,
            isValid: true,
            timestamp: new Date()
          });
          this.currentMessage = '';
          return;
        }

        // Decrypt and verify message from other user
        try {
          const result = await this.cryptoService.decryptMessage(
            encryptedMsg,
            hmac,
            signature,
            sender
          );

          // Add to messages list
          this.messages.push({
            from: sender,
            to: recipient,
            text: result.message,
            isValid: result.isValid,
            timestamp: new Date()
          });
        } catch (error: unknown) {
          console.error('Error processing message:', error);

          // Get error message with proper type handling
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';

          // Still add message but mark as invalid
          this.messages.push({
            from: sender,
            to: recipient,
            text: 'Unable to decrypt message: ' + errorMessage,
            isValid: false,
            timestamp: new Date()
          });
        }
      }
    );

    // Handle message rejection
    this.signalrService.onMessageRejected((reason: string) => {
      console.error('Message rejected by server:', reason);

      // Add error message
      if (this.selectedUser) {
        this.messages.push({
          from: 'System',
          to: this.username,
          text: `Message to ${this.selectedUser} was rejected: ${reason}`,
          isValid: false,
          timestamp: new Date()
        });
      }
    });

    // Handle key updates
    this.signalrService.onKeysUpdated((username: string) => {
      console.log(`${username} has updated their keys, key exchange needed`);
      this.keyExchangeCompleted.delete(username);

      // If this is the currently selected user, show a notification
      if (this.selectedUser === username) {
        this.messages.push({
          from: 'System',
          to: this.username,
          text: `${username} has updated their encryption keys. Key exchange initiated.`,
          isValid: true,
          timestamp: new Date()
        });
      }
    });
  }

  async connectToChat() {
    if (!this.username.trim()) {
      alert('Please enter a username');
      return;
    }

    this.connecting = true;

    try {
      // Initialize cryptographic keys
      const keys = await this.cryptoService.initializeKeys();

      // Register with the server
      await this.signalrService.registerUser(
        this.username,
        keys.publicKey,
        keys.signingPublicKey
      );

      this.isConnected = true;
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Failed to connect:', errorMessage);
      alert('Failed to connect: ' + errorMessage);
    } finally {
      this.connecting = false;
    }
  }

  selectUser(username: string) {
    this.selectedUser = username;

    // Request public keys if not already available
    if (!this.publicKeys.has(username)) {
      this.signalrService.getPublicKey(username);
    }
  }

  isKeyExchangeComplete(username: string): boolean {
    return this.keyExchangeCompleted.has(username);
  }

  private async computeSharedSecret(username: string, publicKey: string): Promise<void> {
    try {
      await this.cryptoService.computeSharedSecret(publicKey, username);
      this.keyExchangeCompleted.add(username);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error(`Error computing shared secret with ${username}:`, errorMessage);
    }
  }

  async sendMessage() {
    if (!this.currentMessage.trim() || !this.selectedUser) {
      return;
    }

    if (!this.isKeyExchangeComplete(this.selectedUser)) {
      alert('Cannot send message: Key exchange not completed');
      return;
    }

    try {
      console.log(`Sending message to ${this.selectedUser}, length: ${this.currentMessage.length}`);

      // Encrypt the message for the selected user
      const result = await this.cryptoService.encryptMessage(
        this.currentMessage,
        this.selectedUser
      );

      console.log("Encrypted message generated");

      // Send encrypted message through SignalR
      await this.signalrService.sendMessage(
        this.selectedUser,
        result.encryptedMessage,
        result.hmac,
        result.signature
      );

      console.log("Message sent to server");

    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Error sending message:', errorMessage);
      alert('Failed to send message: ' + errorMessage);
    }
  }

  getMessagesForUser(username: string) {
    return this.messages.filter(
      msg => (msg.from === username && msg.to === this.username) ||
        (msg.from === this.username && msg.to === username) ||
        (msg.from === 'System' && msg.to === this.username)
    ).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
}
