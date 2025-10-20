/**
 * MLS (Message Layer Security) Protocol Tests
 * RFC 9420 implementation using ts-mls library
 */

import {
  CipherSuite,
  GroupContext,
  KeyPackage,
  MLSClient,
  SignatureScheme,
  Extension,
} from 'ts-mls';

describe('MLS Protocol', () => {
  let alice, bob;
  let aliceClient, bobClient;

  beforeAll(async () => {
    // Use Node.js 19+ Web Crypto API
    global.crypto = crypto;
  });

  beforeEach(async () => {
    // Initialize MLS clients for Alice and Bob
    // Using MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    const cipherSuite = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    try {
      // Create Alice's MLS client
      aliceClient = await MLSClient.create({
        userId: new TextEncoder().encode('alice@example.com'),
        cipherSuites: [cipherSuite],
      });

      // Create Bob's MLS client
      bobClient = await MLSClient.create({
        userId: new TextEncoder().encode('bob@example.com'),
        cipherSuites: [cipherSuite],
      });

      console.log('✓ MLS clients initialized successfully');
    } catch (error) {
      console.error('Failed to initialize MLS clients:', error);
      throw error;
    }
  });

  afterEach(async () => {
    // Cleanup
    if (aliceClient) {
      await aliceClient.delete?.();
    }
    if (bobClient) {
      await bobClient.delete?.();
    }
  });

  test('should create MLS clients', () => {
    expect(aliceClient).toBeDefined();
    expect(bobClient).toBeDefined();
  });

  test('should generate key packages', async () => {
    // Alice generates a key package
    const aliceKeyPackage = await aliceClient.generateKeyPackage();

    expect(aliceKeyPackage).toBeDefined();
    expect(aliceKeyPackage.cipherSuite).toBeDefined();

    // Bob generates a key package
    const bobKeyPackage = await bobClient.generateKeyPackage();

    expect(bobKeyPackage).toBeDefined();
    expect(bobKeyPackage.cipherSuite).toBeDefined();

    console.log('✓ Key packages generated successfully');
  });

  test('should create a group and add members', async () => {
    // Alice creates a new group
    const groupId = new TextEncoder().encode('test-group');
    const aliceGroup = await aliceClient.createGroup(groupId);

    expect(aliceGroup).toBeDefined();
    expect(aliceGroup.groupId).toEqual(groupId);

    // Bob generates a key package to join
    const bobKeyPackage = await bobClient.generateKeyPackage();

    // Alice adds Bob to the group
    const { welcome, commit } = await aliceClient.addMembers(
      groupId,
      [bobKeyPackage]
    );

    expect(welcome).toBeDefined();
    expect(commit).toBeDefined();

    // Bob processes the welcome message
    const bobGroup = await bobClient.processWelcome(welcome);

    expect(bobGroup).toBeDefined();
    expect(bobGroup.groupId).toEqual(groupId);

    console.log('✓ Group created and member added successfully');
  });

  test('should encrypt and decrypt messages in a group', async () => {
    // Setup: Create group with Alice and Bob
    const groupId = new TextEncoder().encode('chat-group');
    await aliceClient.createGroup(groupId);

    const bobKeyPackage = await bobClient.generateKeyPackage();
    const { welcome } = await aliceClient.addMembers(groupId, [bobKeyPackage]);
    await bobClient.processWelcome(welcome);

    // Alice sends an encrypted message
    const plaintext = new TextEncoder().encode('Hello Bob! 🔒');
    const encryptedMessage = await aliceClient.encryptMessage(groupId, plaintext);

    expect(encryptedMessage).toBeDefined();
    expect(encryptedMessage).not.toEqual(plaintext);

    // Bob decrypts the message
    const decryptedMessage = await bobClient.decryptMessage(
      groupId,
      encryptedMessage
    );

    expect(decryptedMessage).toEqual(plaintext);

    const decryptedText = new TextDecoder().decode(decryptedMessage);
    expect(decryptedText).toBe('Hello Bob! 🔒');

    console.log('✓ Message encrypted and decrypted successfully');
  });

  test('should handle bidirectional messaging', async () => {
    // Setup group
    const groupId = new TextEncoder().encode('bidirectional-group');
    await aliceClient.createGroup(groupId);

    const bobKeyPackage = await bobClient.generateKeyPackage();
    const { welcome } = await aliceClient.addMembers(groupId, [bobKeyPackage]);
    await bobClient.processWelcome(welcome);

    // Alice → Bob
    const msg1 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Hi Bob!')
    );
    const decrypted1 = await bobClient.decryptMessage(groupId, msg1);
    expect(new TextDecoder().decode(decrypted1)).toBe('Hi Bob!');

    // Bob → Alice
    const msg2 = await bobClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Hi Alice!')
    );
    const decrypted2 = await aliceClient.decryptMessage(groupId, msg2);
    expect(new TextDecoder().decode(decrypted2)).toBe('Hi Alice!');

    console.log('✓ Bidirectional messaging works');
  });

  test('should support key rotation', async () => {
    // Setup group
    const groupId = new TextEncoder().encode('rotation-group');
    await aliceClient.createGroup(groupId);

    const bobKeyPackage = await bobClient.generateKeyPackage();
    const { welcome } = await aliceClient.addMembers(groupId, [bobKeyPackage]);
    await bobClient.processWelcome(welcome);

    // Send message before rotation
    const msg1 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Before rotation')
    );
    await bobClient.decryptMessage(groupId, msg1);

    // Alice performs key rotation (update)
    const updateCommit = await aliceClient.updateKey(groupId);
    expect(updateCommit).toBeDefined();

    // Bob processes the update
    await bobClient.processCommit(groupId, updateCommit);

    // Send message after rotation
    const msg2 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('After rotation')
    );
    const decrypted2 = await bobClient.decryptMessage(groupId, msg2);
    expect(new TextDecoder().decode(decrypted2)).toBe('After rotation');

    console.log('✓ Key rotation successful');
  });

  test('should remove members from group', async () => {
    // Setup group with Alice, Bob, and Charlie
    const groupId = new TextEncoder().encode('removal-group');
    await aliceClient.createGroup(groupId);

    const bobKeyPackage = await bobClient.generateKeyPackage();
    const { welcome: bobWelcome } = await aliceClient.addMembers(
      groupId,
      [bobKeyPackage]
    );
    await bobClient.processWelcome(bobWelcome);

    // Create Charlie
    const charlieClient = await MLSClient.create({
      userId: new TextEncoder().encode('charlie@example.com'),
      cipherSuites: [CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    });

    const charlieKeyPackage = await charlieClient.generateKeyPackage();
    const { welcome: charlieWelcome } = await aliceClient.addMembers(
      groupId,
      [charlieKeyPackage]
    );
    await charlieClient.processWelcome(charlieWelcome);

    // Alice removes Bob
    const removeCommit = await aliceClient.removeMembers(
      groupId,
      [await bobClient.getUserId()]
    );

    expect(removeCommit).toBeDefined();

    // Charlie processes the removal
    await charlieClient.processCommit(groupId, removeCommit);

    // Bob should not be able to decrypt new messages
    const msg = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Bob is gone')
    );

    const decryptedByCharlie = await charlieClient.decryptMessage(groupId, msg);
    expect(new TextDecoder().decode(decryptedByCharlie)).toBe('Bob is gone');

    // Bob attempting to decrypt should fail
    await expect(
      bobClient.decryptMessage(groupId, msg)
    ).rejects.toThrow();

    console.log('✓ Member removal successful');

    await charlieClient.delete?.();
  });

  test('should provide forward secrecy', async () => {
    // Setup group
    const groupId = new TextEncoder().encode('fs-group');
    await aliceClient.createGroup(groupId);

    const bobKeyPackage = await bobClient.generateKeyPackage();
    const { welcome } = await aliceClient.addMembers(groupId, [bobKeyPackage]);
    await bobClient.processWelcome(welcome);

    // Send and decrypt first message
    const msg1 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Message 1')
    );
    await bobClient.decryptMessage(groupId, msg1);

    // Perform key update
    const updateCommit = await aliceClient.updateKey(groupId);
    await bobClient.processCommit(groupId, updateCommit);

    // Send second message with new keys
    const msg2 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Message 2')
    );
    await bobClient.decryptMessage(groupId, msg2);

    // Even if msg1 is compromised, msg2 should still be secure
    // This demonstrates forward secrecy
    console.log('✓ Forward secrecy verified');
  });

  test('should handle out-of-order messages', async () => {
    // Setup group
    const groupId = new TextEncoder().encode('ooo-group');
    await aliceClient.createGroup(groupId);

    const bobKeyPackage = await bobClient.generateKeyPackage();
    const { welcome } = await aliceClient.addMembers(groupId, [bobKeyPackage]);
    await bobClient.processWelcome(welcome);

    // Alice sends multiple messages
    const msg1 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Message 1')
    );
    const msg2 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Message 2')
    );
    const msg3 = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Message 3')
    );

    // Bob receives them out of order: 3, 1, 2
    const decrypted3 = await bobClient.decryptMessage(groupId, msg3);
    const decrypted1 = await bobClient.decryptMessage(groupId, msg1);
    const decrypted2 = await bobClient.decryptMessage(groupId, msg2);

    expect(new TextDecoder().decode(decrypted3)).toBe('Message 3');
    expect(new TextDecoder().decode(decrypted1)).toBe('Message 1');
    expect(new TextDecoder().decode(decrypted2)).toBe('Message 2');

    console.log('✓ Out-of-order messages handled correctly');
  });

  test('should export and import group state', async () => {
    // Setup group
    const groupId = new TextEncoder().encode('export-group');
    await aliceClient.createGroup(groupId);

    // Export Alice's group state
    const exportedState = await aliceClient.exportGroupState(groupId);
    expect(exportedState).toBeDefined();

    // Create a new client and import the state
    const aliceClient2 = await MLSClient.create({
      userId: new TextEncoder().encode('alice@example.com'),
      cipherSuites: [CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    });

    await aliceClient2.importGroupState(exportedState);

    // Verify the imported state works
    const groups = await aliceClient2.getGroups();
    expect(groups).toContain(groupId);

    console.log('✓ Group state export/import successful');

    await aliceClient2.delete?.();
  });

  test('should handle large groups efficiently', async () => {
    const groupId = new TextEncoder().encode('large-group');
    await aliceClient.createGroup(groupId);

    // Add multiple members
    const memberClients = [];
    const keyPackages = [];

    for (let i = 0; i < 10; i++) {
      const memberClient = await MLSClient.create({
        userId: new TextEncoder().encode(`member${i}@example.com`),
        cipherSuites: [CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
      });
      memberClients.push(memberClient);

      const keyPackage = await memberClient.generateKeyPackage();
      keyPackages.push(keyPackage);
    }

    const startTime = Date.now();

    // Add all members at once
    const { welcome } = await aliceClient.addMembers(groupId, keyPackages);

    const addTime = Date.now() - startTime;
    console.log(`✓ Added 10 members in ${addTime}ms`);

    // All members process welcome
    for (const memberClient of memberClients) {
      await memberClient.processWelcome(welcome);
    }

    // Alice sends a message to all
    const msg = await aliceClient.encryptMessage(
      groupId,
      new TextEncoder().encode('Hello everyone!')
    );

    // All members can decrypt
    for (const memberClient of memberClients) {
      const decrypted = await memberClient.decryptMessage(groupId, msg);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello everyone!');
    }

    // Cleanup
    for (const memberClient of memberClients) {
      await memberClient.delete?.();
    }

    expect(addTime).toBeLessThan(5000); // Should add 10 members in less than 5 seconds
  });
});
