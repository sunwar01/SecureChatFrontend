import { Injectable } from '@angular/core';
import * as signalR from '@microsoft/signalr';

@Injectable({
  providedIn: 'root'
})
export class SignalrService {
  private hubConnection: signalR.HubConnection | null = null;
  private readonly hubUrl = 'http://localhost:5155/chat'; // Update with your API URL

  constructor() { }



  // Start SignalR connection
  async startConnection(): Promise<void> {
    this.hubConnection = new signalR.HubConnectionBuilder()
      .withUrl(this.hubUrl)
      .withAutomaticReconnect()
      .build();

    try {
      await this.hubConnection.start();
      console.log('SignalR connection started');
    } catch (error) {
      console.error('Error starting SignalR connection:', error);
      throw error;
    }
  }

  // Stop SignalR connection
  async stopConnection(): Promise<void> {
    if (this.hubConnection) {
      try {
        await this.hubConnection.stop();
        console.log('SignalR connection stopped');
      } catch (error) {
        console.error('Error stopping SignalR connection:', error);
      }
    }
  }

  // Register SignalR event handlers
  async registerUser(
    username: string,
    publicKey: string,
    signingPublicKey: string
  ): Promise<void> {
    if (!this.hubConnection) {
      throw new Error('Connection not established');
    }

    await this.hubConnection.invoke('RegisterUser', username, publicKey, signingPublicKey);
  }

  // Send message to user
  async sendMessage(
    recipientUsername: string,
    encryptedMessage: string,
    hmac: string,
    signature: string
  ): Promise<void> {
    if (!this.hubConnection) {
      throw new Error('Connection not established');
    }

    await this.hubConnection.invoke(
      'SendMessage',
      recipientUsername,
      encryptedMessage,
      hmac,
      signature
    );
  }

  // Request public key from user
  async getPublicKey(username: string): Promise<void> {
    if (!this.hubConnection) {
      throw new Error('Connection not established');
    }

    await this.hubConnection.invoke('GetPublicKey', username);
  }





  // Handle server requesting user info

  onRequestUserInfo(callback: () => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('RequestUserInfo', callback);
  }

  // Handle user list updates
  onUserList(callback: (users: string[]) => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('UserList', callback);
  }

  // Handle user disconnect
  onUserDisconnected(callback: (username: string) => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('UserDisconnected', callback);
  }

  // Handle receiving public key
  onPublicKey(callback: (username: string, publicKey: string) => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('PublicKey', callback);
  }

  // Handle receiving signing public key
  onSigningPublicKey(callback: (username: string, publicKey: string) => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('SigningPublicKey', callback);
  }

  // Handle receiving message
  onReceiveMessage(
    callback: (
      sender: string,
      recipient: string,
      encryptedMessage: string,
      hmac: string,
      signature: string
    ) => void
  ): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('ReceiveMessage', callback);
  }

  // Handle message rejection
  onMessageRejected(callback: (reason: string) => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('MessageRejected', callback);
  }

  //Handle notification of key updates
  onKeysUpdated(callback: (username: string) => void): void {
    if (!this.hubConnection) {
      return;
    }

    this.hubConnection.on('KeysUpdated', callback);
  }
}
