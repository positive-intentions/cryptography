/**
 * Mock MLS Manager for Jest tests
 * This mock simulates the MLS protocol behavior for unit testing
 * Real implementation is tested in Storybook (browser environment)
 *
 * This mock avoids ES module import issues with ts-mls during Jest testing
 */

// Helper to strip trailing null nodes per RFC 9420
function stripTrailingNulls(tree: any[]): any[] {
  let lastNonNull = tree.length - 1;
  while (lastNonNull >= 0 && tree[lastNonNull] === null) {
    lastNonNull--;
  }
  return tree.slice(0, lastNonNull + 1);
}

export class MLSManager {
  private userId: string;
  private initialized: boolean = false;
  private groups: Map<string, any> = new Map();
  private keyPackage: any = null;

  constructor(userId: string) {
    this.userId = userId;
  }

  /**
   * Initialize the MLS manager
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    this.initialized = true;

    // Generate mock key package
    this.keyPackage = {
      publicPackage: {
        version: 'mls10',
        cipherSuite: 1,
        initKey: new Uint8Array(32),
        leafNode: {
          credential: {
            credentialType: 'basic',
            identity: new TextEncoder().encode(this.userId)
          },
          capabilities: {},
          encryptionKey: new Uint8Array(32),
          signatureKey: new Uint8Array(32)
        },
        signature: new Uint8Array(64)
      },
      privatePackage: {
        initPrivKey: new Uint8Array(32),
        encryptionPrivKey: new Uint8Array(32),
        signaturePrivKey: new Uint8Array(64)
      },
      userId: this.userId
    };
  }

  /**
   * Generate a new key package
   */
  async generateKeyPackage(): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }
    return this.keyPackage;
  }

  /**
   * Get the current key package
   */
  getKeyPackage(): any {
    return this.keyPackage;
  }

  /**
   * Get user ID
   */
  getUserId(): string {
    return this.userId;
  }

  /**
   * Create a new MLS group
   */
  async createGroup(groupId: string): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const groupIdBytes = new TextEncoder().encode(groupId);
    const mockGroup = {
      groupId: groupIdBytes,
      members: [this.userId],
      epoch: 0n,
      treeHash: new Uint8Array(32).fill(Math.random() * 255)
    };

    this.groups.set(groupId, mockGroup);
    return mockGroup;
  }

  /**
   * Add members to a group
   */
  async addMembers(groupId: string, keyPackages: any[]): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const group = this.groups.get(groupId);
    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    // Add new members
    for (const kp of keyPackages) {
      if (!group.members.includes(kp.userId)) {
        group.members.push(kp.userId);
      }
    }

    // Increment epoch
    group.epoch = BigInt(group.epoch) + 1n;

    // Update tree hash
    group.treeHash = new Uint8Array(32).fill(Math.random() * 255);

    // Create mock ratchet tree with nulls to simulate MLS binary tree structure
    // For a 2-member group, we have: [leaf0, parent (null), leaf1, ...]
    // Binary tree pre-allocates space, so it's larger than just the members
    const memberCount = group.members.length;
    const treeSize = Math.pow(2, Math.ceil(Math.log2(memberCount + 1))) * 2 - 1;
    const mockRatchetTree = new Array(treeSize).fill(null);

    // Place leaf nodes at even indices (0, 2, 4, ...)
    for (let i = 0; i < memberCount; i++) {
      mockRatchetTree[i * 2] = {
        nodeType: 'leaf',
        leaf: {
          credential: {
            identity: new TextEncoder().encode(group.members[i])
          },
          publicKey: new Uint8Array(32).fill(i)
        }
      };
    }

    // Return mock welcome and commit
    // Store group ID in welcome for processWelcome to use
    const welcome = {
      version: 'mls10',
      cipherSuite: 1,
      secrets: new Uint8Array(32),
      encryptedGroupInfo: new Uint8Array(128),
      _mockGroupId: groupId, // Internal mock field
      _mockMembers: [...group.members] // Copy of current members
    };

    const commit = {
      version: 'mls10',
      wireformat: 'mls_private_message',
      privateMessage: {
        groupId: group.groupId,
        epoch: group.epoch - 1n,
        content: {
          contentType: 'commit',
          proposals: keyPackages.map(kp => ({
            proposalType: 'add',
            add: { keyPackage: kp.publicPackage }
          }))
        }
      }
    };

    // RFC 9420: Strip trailing null nodes before transmission
    const strippedTree = stripTrailingNulls(mockRatchetTree);

    return {
      welcome,
      commit,
      ratchetTree: strippedTree
    };
  }

  /**
   * Process welcome message to join a group
   */
  async processWelcome(welcome: any, ratchetTree?: any): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    // Extract group ID from welcome message (mock internal field)
    const groupId = welcome._mockGroupId || 'default-group';
    const groupIdBytes = new TextEncoder().encode(groupId);

    // Get existing members from welcome
    const existingMembers = welcome._mockMembers || [];

    // Create the group in this manager's map with the same ID
    // Only add self if not already in members list
    const members = existingMembers.includes(this.userId)
      ? existingMembers
      : [...existingMembers, this.userId];

    const mockGroup = {
      groupId: groupIdBytes,
      members,
      epoch: 1n,
      treeHash: ratchetTree || new Uint8Array(32)
    };

    this.groups.set(groupId, mockGroup);

    return {
      groupId: mockGroup.groupId,
      members: mockGroup.members,
      epoch: mockGroup.epoch
    };
  }

  /**
   * Encrypt a message for a group
   */
  async encryptMessage(groupId: string, plaintext: string): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const group = this.groups.get(groupId);
    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    // Mock encryption - add randomness to ensure different ciphertexts
    const nonce = Math.random().toString(36).substring(7);
    const ciphertext = Buffer.from(`encrypted:${plaintext}:${group.epoch}:${nonce}`).toString('base64');

    return {
      groupId: new TextEncoder().encode(groupId),
      ciphertext: new TextEncoder().encode(ciphertext),
      timestamp: Date.now()
    };
  }

  /**
   * Decrypt a message from a group
   */
  async decryptMessage(envelope: any): Promise<string> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const groupId = new TextDecoder().decode(envelope.groupId);
    const group = this.groups.get(groupId);

    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    // Check if this user is still a member of the group
    if (!group.members.includes(this.userId)) {
      throw new Error('Cannot decrypt: user is not a member of this group');
    }

    // Mock decryption - decode base64 and extract plaintext
    let ciphertextStr: string;
    try {
      ciphertextStr = new TextDecoder().decode(envelope.ciphertext);
    } catch (e) {
      throw new Error(`Invalid ciphertext format: failed to decode Uint8Array to string: ${e.message}`);
    }

    let decoded: string;
    try {
      decoded = Buffer.from(ciphertextStr, 'base64').toString('utf-8');
    } catch (e) {
      throw new Error(`Invalid ciphertext format: failed to decode base64 string: ${e.message}. Ciphertext length: ${ciphertextStr.length}`);
    }

    const parts = decoded.split(':');

    if (parts[0] !== 'encrypted') {
      throw new Error(`Invalid ciphertext format: expected to start with "encrypted:", got "${decoded.substring(0, Math.min(50, decoded.length))}..."`);
    }

    return parts[1]; // Return the plaintext part
  }

  /**
   * Perform key rotation (update)
   */
  async updateKey(groupId: string): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const group = this.groups.get(groupId);
    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    // Increment epoch for key rotation
    group.epoch = BigInt(group.epoch) + 1n;

    // Update tree hash
    group.treeHash = new Uint8Array(32).fill(Math.random() * 255);

    // Return mock commit
    return {
      version: 'mls10',
      wireformat: 'mls_private_message',
      privateMessage: {
        groupId: group.groupId,
        epoch: group.epoch - 1n,
        content: {
          contentType: 'commit',
          proposals: [{
            proposalType: 'update',
            update: {
              leafNode: this.keyPackage.publicPackage.leafNode
            }
          }]
        }
      }
    };
  }

  /**
   * Process a commit message
   */
  async processCommit(groupId: string, commit: any): Promise<void> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const group = this.groups.get(groupId);
    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    // Extract private message
    const privateMessage = commit.privateMessage || commit;

    // Process proposals if they exist
    if (privateMessage.content && privateMessage.content.proposals) {
      for (const proposal of privateMessage.content.proposals) {
        if (proposal.proposalType === 'remove') {
          // Handle member removal
          const removeIndex = Number(proposal.remove?.removed || 0);
          if (removeIndex >= 0 && removeIndex < group.members.length) {
            group.members.splice(removeIndex, 1);
          }
        }
      }
    }

    // Increment epoch to match sender
    group.epoch = BigInt(group.epoch) + 1n;

    // Update tree hash
    group.treeHash = new Uint8Array(32).fill(Math.random() * 255);
  }

  /**
   * Remove members from a group
   */
  async removeMembers(groupId: string, memberIndices: number[]): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const group = this.groups.get(groupId);
    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    // Remove members by index (sort in reverse to maintain indices)
    for (const index of memberIndices.sort((a, b) => b - a)) {
      if (index >= 0 && index < group.members.length) {
        group.members.splice(index, 1);
      }
    }

    // Increment epoch
    group.epoch = BigInt(group.epoch) + 1n;

    // Return mock commit with removal proposals
    return {
      version: 'mls10',
      wireformat: 'mls_private_message',
      privateMessage: {
        groupId: group.groupId,
        epoch: group.epoch - 1n,
        content: {
          contentType: 'commit',
          proposals: memberIndices.map(index => ({
            proposalType: 'remove',
            remove: {
              removed: BigInt(index)
            }
          }))
        }
      }
    };
  }

  /**
   * Get list of groups
   */
  async getGroups(): Promise<Uint8Array[]> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    return Array.from(this.groups.keys()).map(id => new TextEncoder().encode(id));
  }

  /**
   * Get group metadata
   */
  async getGroupKeyInfo(groupId: string): Promise<any> {
    const group = this.groups.get(groupId);

    if (!group) {
      return null;
    }

    return {
      groupId,
      epoch: group.epoch.toString(),
      members: group.members,
      cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
      treeHash: Buffer.from(group.treeHash).toString('hex').substring(0, 16)
    };
  }

  /**
   * Export group state
   */
  async exportGroupState(groupId: string): Promise<any> {
    if (!this.initialized) {
      throw new Error('MLS Manager not initialized. Call initialize() first.');
    }

    const group = this.groups.get(groupId);
    if (!group) {
      throw new Error(`Group ${groupId} not found`);
    }

    return {
      groupId,
      epoch: group.epoch.toString(),
      exported: Date.now()
    };
  }

  /**
   * Clean up resources
   */
  async destroy(): Promise<void> {
    this.groups.clear();
    this.keyPackage = null;
    this.initialized = false;
  }
}

export default MLSManager;
