/**
 * MLS (Message Layer Security) Manager
 * RFC 9420 implementation using ts-mls library
 * Provides end-to-end encrypted group messaging with forward secrecy
 */

import {
  createApplicationMessage,
  createCommit,
  createGroup,
  joinGroup,
  processPrivateMessage,
  processPublicMessage,
  getCiphersuiteFromName,
  generateKeyPackage,
  encodeMlsMessage,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  nobleCryptoProvider,
  type ClientState,
  type Credential,
  type Proposal,
  type PrivateKeyPackage,
  type KeyPackage,
  type Welcome,
  type PrivateMessage,
  type CiphersuiteImpl,
} from 'ts-mls';

export interface MLSGroupInfo {
  groupId: Uint8Array;
  members: string[];
  epoch: bigint;
}

export interface MLSMessageEnvelope {
  groupId: Uint8Array;
  ciphertext: Uint8Array;
  timestamp: number;
}

export interface MLSKeyPackageBundle {
  publicPackage: KeyPackage;
  privatePackage: PrivateKeyPackage;
  userId: string;
}

/**
 * MLSManager wraps the ts-mls functional API with a class-based interface
 * for easier state management in applications
 */
export class MLSManager {
  private userId: string;
  private cipherSuite: CiphersuiteImpl | null = null;
  private initialized: boolean = false;
  private groups: Map<string, ClientState> = new Map();
  private keyPackage: MLSKeyPackageBundle | null = null;
  private credential: Credential;

  constructor(userId: string) {
    this.userId = userId;
    this.credential = {
      credentialType: 'basic',
      identity: new TextEncoder().encode(userId),
    };
  }

  /**
   * Initialize the MLS client with a ciphersuite
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      console.warn('MLS Manager already initialized');
      return;
    }

    try {
      console.log(`🔐 [MLS] Initializing for user: ${this.userId}`);

      // Use MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (ID: 1)
      // Using nobleCryptoProvider for compatibility (pure JS implementation)
      const cipherSuiteName = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
      const cs = getCiphersuiteFromName(cipherSuiteName);
      this.cipherSuite = await nobleCryptoProvider.getCiphersuiteImpl(cs);

      console.log(`✅ [MLS] Using ciphersuite: ${cipherSuiteName}`);

      // Mark as initialized before generating key package
      this.initialized = true;

      // Generate initial key package for this user
      await this.generateKeyPackage();

      console.log('✅ [MLS] Initialized successfully');
    } catch (error) {
      console.error('❌ [MLS] Failed to initialize:', error);
      throw new Error(`MLS initialization failed: ${error.message}`);
    }
  }

  /**
   * Generate a new key package for joining groups
   */
  async generateKeyPackage(): Promise<MLSKeyPackageBundle> {
    this.ensureInitialized();

    try {
      console.log('🔑 [MLS] Generating key package');

      const keyPackageResult = await generateKeyPackage(
        this.credential,
        defaultCapabilities(),
        defaultLifetime,
        [],
        this.cipherSuite!
      );

      this.keyPackage = {
        ...keyPackageResult,
        userId: this.userId,
      };

      console.log('✅ [MLS] Key package generated');
      return this.keyPackage;
    } catch (error) {
      console.error('❌ [MLS] Failed to generate key package:', error);
      throw new Error(`Key package generation failed: ${error.message}`);
    }
  }

  /**
   * Get the current key package
   */
  getKeyPackage(): MLSKeyPackageBundle | null {
    return this.keyPackage;
  }

  /**
   * Create a new MLS group
   */
  async createGroup(groupId: string): Promise<MLSGroupInfo> {
    this.ensureInitialized();

    try {
      console.log(`📝 [MLS] Creating group: ${groupId}`);

      if (!this.keyPackage) {
        throw new Error('No key package available. Call generateKeyPackage() first.');
      }

      const groupIdBytes = new TextEncoder().encode(groupId);

      // Create group using ts-mls
      const groupState = await createGroup(
        groupIdBytes,
        this.keyPackage.publicPackage,
        this.keyPackage.privatePackage,
        [],
        this.cipherSuite!
      );

      this.groups.set(groupId, groupState);

      const groupInfo: MLSGroupInfo = {
        groupId: groupIdBytes,
        members: [this.userId],
        epoch: groupState.groupContext.epoch,
      };

      console.log(`✅ [MLS] Group created: ${groupId}, epoch: ${groupState.groupContext.epoch}`);
      return groupInfo;
    } catch (error) {
      console.error('❌ [MLS] Failed to create group:', error);
      throw new Error(`Group creation failed: ${error.message}`);
    }
  }

  /**
   * Add members to an existing group
   */
  async addMembers(
    groupId: string,
    keyPackages: MLSKeyPackageBundle[]
  ): Promise<{ welcome: Welcome; ratchetTree: any; commit: any }> {
    this.ensureInitialized();

    try {
      console.log(`➕ [MLS] Adding ${keyPackages.length} member(s) to group: ${groupId}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      // Create add proposals for each key package
      const addProposals: Proposal[] = keyPackages.map((kp) => ({
        proposalType: 'add',
        add: {
          keyPackage: kp.publicPackage,
        },
      }));

      // Create commit with add proposals
      const commitResult = await createCommit(
        { state: groupState, cipherSuite: this.cipherSuite! },
        { extraProposals: addProposals }
      );

      // Update group state
      this.groups.set(groupId, commitResult.newState);

      if (!commitResult.welcome) {
        throw new Error('No welcome message generated');
      }

      console.log(
        `✅ [MLS] Members added, new epoch: ${commitResult.newState.groupContext.epoch}`
      );

      // Debug: Log the commit structure
      console.group('🔍 [MLS Debug] Commit Structure');
      console.log('commitResult keys:', Object.keys(commitResult));
      console.log('commit:', commitResult.commit);
      console.log('commit.privateMessage:', commitResult.commit?.privateMessage);
      console.groupEnd();

      // Return welcome and ratchet tree
      // NOTE: Commit distribution to existing members might not be needed/supported
      return {
        welcome: commitResult.welcome,
        ratchetTree: commitResult.newState.ratchetTree,
        commit: commitResult.commit,
      };
    } catch (error) {
      console.error('❌ [MLS] Failed to add members:', error);
      throw new Error(`Adding members failed: ${error.message}`);
    }
  }

  /**
   * Process a welcome message to join a group
   */
  async processWelcome(
    welcome: Welcome,
    ratchetTree?: Uint8Array[]
  ): Promise<MLSGroupInfo> {
    this.ensureInitialized();

    try {
      console.log('📩 [MLS] Processing welcome message');

      if (!this.keyPackage) {
        throw new Error('No key package available');
      }

      // Join group using ts-mls
      const groupState = await joinGroup(
        welcome,
        this.keyPackage.publicPackage,
        this.keyPackage.privatePackage,
        emptyPskIndex,
        this.cipherSuite!,
        ratchetTree
      );

      const groupId = new TextDecoder().decode(groupState.groupContext.groupId);
      this.groups.set(groupId, groupState);

      // Extract member identities from ratchet tree
      const members = this.extractMembersFromState(groupState);

      const groupInfo: MLSGroupInfo = {
        groupId: groupState.groupContext.groupId,
        members,
        epoch: groupState.groupContext.epoch,
      };

      console.log(`✅ [MLS] Welcome processed, joined group: ${groupId}`);
      return groupInfo;
    } catch (error) {
      console.error('❌ [MLS] Failed to process welcome:', error);
      throw new Error(`Welcome processing failed: ${error.message}`);
    }
  }

  /**
   * Encrypt a message for a group
   */
  async encryptMessage(groupId: string, plaintext: string): Promise<MLSMessageEnvelope> {
    this.ensureInitialized();

    try {
      console.log(`🔒 [MLS] Encrypting message for group: ${groupId}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      const plaintextBytes = new TextEncoder().encode(plaintext);

      // Create application message
      const result = await createApplicationMessage(
        groupState,
        plaintextBytes,
        this.cipherSuite!
      );

      // Update group state (for key ratcheting)
      this.groups.set(groupId, result.newState);

      // Encode the private message
      const encoded = encodeMlsMessage({
        privateMessage: result.privateMessage,
        wireformat: 'mls_private_message',
        version: 'mls10',
      });

      const envelope: MLSMessageEnvelope = {
        groupId: new TextEncoder().encode(groupId),
        ciphertext: encoded,
        timestamp: Date.now(),
      };

      console.log('✅ [MLS] Message encrypted');
      return envelope;
    } catch (error) {
      console.error('❌ [MLS] Failed to encrypt message:', error);
      throw new Error(`Message encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt a message from a group
   */
  async decryptMessage(envelope: MLSMessageEnvelope): Promise<string> {
    this.ensureInitialized();

    try {
      const groupId = new TextDecoder().decode(envelope.groupId);
      console.log(`🔓 [MLS] Decrypting message for group: ${groupId}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      // Decode the message
      const decoded = decodeMlsMessage(envelope.ciphertext, 0);
      if (!decoded || decoded.length === 0) {
        throw new Error('Failed to decode message');
      }

      const [decodedMessage] = decoded;
      if (decodedMessage.wireformat !== 'mls_private_message') {
        throw new Error('Expected private message');
      }

      // Process the private message
      const result = await processPrivateMessage(
        groupState,
        decodedMessage.privateMessage,
        emptyPskIndex,
        this.cipherSuite!
      );

      // Update group state
      this.groups.set(groupId, result.newState);

      if (result.kind !== 'applicationMessage') {
        throw new Error('Expected application message');
      }

      const plaintext = new TextDecoder().decode(result.message);

      console.log('✅ [MLS] Message decrypted');
      return plaintext;
    } catch (error) {
      console.error('❌ [MLS] Failed to decrypt message:', error);
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Update the group keys (key rotation)
   */
  async updateKey(groupId: string): Promise<any> {
    this.ensureInitialized();

    try {
      console.log(`🔄 [MLS] Performing key rotation for group: ${groupId}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      // Create update commit (forces path update)
      const commitResult = await createCommit(
        { state: groupState, cipherSuite: this.cipherSuite! },
        { forcePathUpdate: true }
      );

      // Update group state
      this.groups.set(groupId, commitResult.newState);

      console.log(
        `✅ [MLS] Key rotation successful, new epoch: ${commitResult.newState.groupContext.epoch}`
      );

      // Return the raw commit object for other members to process
      return commitResult.commit;
    } catch (error) {
      console.error('❌ [MLS] Failed to update key:', error);
      throw new Error(`Key update failed: ${error.message}`);
    }
  }

  /**
   * Process a commit message (key rotation, member changes)
   *
   * IMPORTANT: Commits from createCommit() are PrivateMessages, not PublicMessages!
   */
  async processCommit(groupId: string, commit: any): Promise<void> {
    this.ensureInitialized();

    try {
      console.log(`⚙️ [MLS] Processing commit for group: ${groupId}`);
      console.log(`🔍 [MLS Debug] Commit wireformat: ${commit.wireformat}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      // The commit is a PrivateMessage, so use processPrivateMessage!
      console.log('🔍 [MLS Debug] Processing as PRIVATE message...');

      const result = await processPrivateMessage(
        groupState,
        commit,
        this.cipherSuite!
      );

      // Update group state
      this.groups.set(groupId, result.newState);

      console.log(`✅ [MLS] Commit processed, epoch: ${result.newState.groupContext.epoch}`);
    } catch (error) {
      console.error('❌ [MLS] Failed to process commit:', error);
      console.error('❌ [MLS Debug] Error details:', error.stack);
      throw new Error(`Commit processing failed: ${error.message}`);
    }
  }

  /**
   * Remove members from a group
   */
  async removeMembers(groupId: string, memberIndices: number[]): Promise<Uint8Array> {
    this.ensureInitialized();

    try {
      console.log(`➖ [MLS] Removing ${memberIndices.length} member(s) from group: ${groupId}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      // Create remove proposals
      const removeProposals: Proposal[] = memberIndices.map((index) => ({
        proposalType: 'remove',
        remove: {
          removed: BigInt(index),
        },
      }));

      // Create commit with remove proposals
      const commitResult = await createCommit(
        { state: groupState, cipherSuite: this.cipherSuite! },
        { extraProposals: removeProposals }
      );

      // Update group state
      this.groups.set(groupId, commitResult.newState);

      // Encode the commit
      const encodedCommit = encodeMlsMessage({
        publicMessage: commitResult.publicMessage!,
        wireformat: 'mls_public_message',
        version: 'mls10',
      });

      console.log('✅ [MLS] Members removed');
      return encodedCommit;
    } catch (error) {
      console.error('❌ [MLS] Failed to remove members:', error);
      throw new Error(`Member removal failed: ${error.message}`);
    }
  }

  /**
   * Get list of groups
   */
  async getGroups(): Promise<Uint8Array[]> {
    this.ensureInitialized();

    try {
      const groupIds = Array.from(this.groups.keys()).map((id) =>
        new TextEncoder().encode(id)
      );
      return groupIds;
    } catch (error) {
      console.error('❌ [MLS] Failed to get groups:', error);
      throw new Error(`Getting groups failed: ${error.message}`);
    }
  }

  /**
   * Export group state for persistence
   */
  async exportGroupState(groupId: string): Promise<any> {
    this.ensureInitialized();

    try {
      console.log(`💾 [MLS] Exporting state for group: ${groupId}`);

      const groupState = this.groups.get(groupId);
      if (!groupState) {
        throw new Error(`Group ${groupId} not found`);
      }

      // Note: ts-mls ClientState contains non-serializable crypto keys
      // This is a simplified export - in production you'd need proper serialization
      const exportData = {
        groupId,
        epoch: groupState.groupContext.epoch.toString(),
        exported: Date.now(),
        // Add other serializable fields as needed
      };

      console.log('✅ [MLS] Group state exported');
      return exportData;
    } catch (error) {
      console.error('❌ [MLS] Failed to export group state:', error);
      throw new Error(`Group state export failed: ${error.message}`);
    }
  }

  /**
   * Get user ID
   */
  getUserId(): string {
    return this.userId;
  }

  /**
   * Get group information
   */
  async getGroupKeyInfo(groupId: string): Promise<any> {
    const groupState = this.groups.get(groupId);

    if (!groupState) {
      return null;
    }

    const members = this.extractMembersFromState(groupState);

    return {
      groupId,
      epoch: groupState.groupContext.epoch.toString(),
      members,
      cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
      treeHash: this.bytesToHex(groupState.groupContext.treeHash).substring(0, 16),
    };
  }

  /**
   * Clean up resources
   */
  async destroy(): Promise<void> {
    this.groups.clear();
    this.keyPackage = null;
    this.initialized = false;
    console.log('✅ [MLS] Manager destroyed');
  }

  /**
   * Extract member identities from group state
   */
  private extractMembersFromState(state: ClientState): string[] {
    const members: string[] = [];

    try {
      // Iterate through ratchet tree to find leaf nodes
      for (let i = 0; i < state.ratchetTree.length; i++) {
        const node = state.ratchetTree[i];
        if (node && node.nodeType === 'leaf' && node.leaf.credential) {
          const identity = new TextDecoder().decode(node.leaf.credential.identity);
          members.push(identity);
        }
      }
    } catch (error) {
      console.warn('Could not extract members:', error);
      members.push(this.userId); // At least include self
    }

    return members;
  }

  /**
   * Convert bytes to hex string
   */
  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Ensure the manager is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }
  }
}

export default MLSManager;
