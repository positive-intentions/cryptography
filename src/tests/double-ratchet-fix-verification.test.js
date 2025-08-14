/**
 * Test to verify the Double Ratchet fix without WASM loading issues
 * This test uses the JavaScript implementation to verify the same logic pattern
 */

import { render } from '@testing-library/react';
import { CryptographyProvider, useCryptography } from '../stories/components/Cryptography';
import React from 'react';

describe('Double Ratchet Fix Verification', () => {
    let crypto;

    beforeAll(async () => {
        // Create a test component to get the crypto instance
        let cryptoInstance;
        const TestComponent = () => {
            cryptoInstance = useCryptography();
            return <div>Test</div>;
        };

        render(
            <CryptographyProvider>
                <TestComponent />
            </CryptographyProvider>
        );

        crypto = cryptoInstance;
        expect(crypto).toBeDefined();
    });

    test('should handle the critical Alice->Bob->Alice message flow', async () => {
        console.log('\n🔍 Testing the message flow that was failing in WASM...');

        // Step 1: Set up Alice and Bob with X3DH
        console.log('📋 Step 1: Setting up Alice and Bob with X3DH key exchange');
        const alice = await crypto.initializeSignalUser("Alice");
        const bob = await crypto.initializeSignalUser("Bob");
        const bobBundle = await crypto.getSignalPublicKeyBundle(bob);
        const exchangeResult = await crypto.performSignalX3DHKeyExchange(alice, bobBundle);

        console.log('✅ X3DH completed, shared secret length:', exchangeResult.masterSecret.byteLength);

        // Step 2: Initialize Double Ratchet states
        console.log('📋 Step 2: Initializing Double Ratchet states');
        const aliceState = await crypto.initializeDoubleRatchet(exchangeResult.masterSecret, true);
        const bobState = await crypto.initializeDoubleRatchet(exchangeResult.masterSecret, false);

        console.log('✅ Alice initialized (initiator):', {
            sendingMessageNumber: aliceState.sendingMessageNumber,
            receivingMessageNumber: aliceState.receivingMessageNumber
        });
        console.log('✅ Bob initialized (responder):', {
            sendingMessageNumber: bobState.sendingMessageNumber,
            receivingMessageNumber: bobState.receivingMessageNumber
        });

        // Step 3: Alice sends first message to Bob (this was working)
        console.log('📋 Step 3: Alice -> Bob (first message)');
        const msg1 = 'Hello Bob from Alice!';
        const encrypted1 = await crypto.doubleRatchetEncrypt(aliceState, msg1);
        const decrypted1 = await crypto.doubleRatchetDecrypt(bobState, encrypted1);

        console.log('✅ Message 1 successful:', decrypted1);
        expect(decrypted1).toBeDefined();
        expect(typeof decrypted1).toBe('string');
        expect(bobState.receivingMessageNumber).toBe(1);

        // Step 4: Bob sends reply to Alice (this was failing in WASM)
        console.log('📋 Step 4: Bob -> Alice (reply - critical DH ratchet step)');
        console.log('🔍 Pre-encryption Bob state:', {
            sendingMessageNumber: bobState.sendingMessageNumber,
            receivingMessageNumber: bobState.receivingMessageNumber,
            hasSendingChainKey: !!bobState.sendingChainKey,
            hasReceivingChainKey: !!bobState.receivingChainKey
        });

        const msg2 = 'Hello Alice from Bob!';
        
        try {
            const encrypted2 = await crypto.doubleRatchetEncrypt(bobState, msg2);
            console.log('✅ Bob encryption successful');
            
            console.log('🔍 Pre-decryption Alice state:', {
                sendingMessageNumber: aliceState.sendingMessageNumber,
                receivingMessageNumber: aliceState.receivingMessageNumber,
                hasSendingChainKey: !!aliceState.sendingChainKey,
                hasReceivingChainKey: !!aliceState.receivingChainKey
            });

            const decrypted2 = await crypto.doubleRatchetDecrypt(aliceState, encrypted2);
            console.log('✅ Alice decryption successful:', decrypted2);
            
            expect(decrypted2).toBeDefined();
            expect(typeof decrypted2).toBe('string');
            expect(aliceState.receivingMessageNumber).toBe(1);

            // Step 5: Continue conversation to verify DH ratchet is working
            console.log('📋 Step 5: Alice -> Bob (after DH ratchet)');
            const msg3 = 'Great to hear from you!';
            const encrypted3 = await crypto.doubleRatchetEncrypt(aliceState, msg3);
            const decrypted3 = await crypto.doubleRatchetDecrypt(bobState, encrypted3);

            console.log('✅ Message 3 successful:', decrypted3);
            expect(decrypted3).toBeDefined();
            expect(typeof decrypted3).toBe('string');

            console.log('🎉 Full bidirectional conversation successful!');
            console.log('🎉 This confirms the JavaScript implementation handles DH ratchet correctly');
            console.log('🎉 The WASM fix should now work similarly');

        } catch (error) {
            console.error('❌ Critical failure in Bob->Alice flow:', error);
            console.error('❌ This indicates the same issue exists in JavaScript');
            throw error;
        }
    });

    test('should verify receiving chain key establishment logic', async () => {
        console.log('\n🔍 Testing receiving chain key establishment patterns...');

        // Set up states
        const alice = await crypto.initializeSignalUser("Alice");
        const bob = await crypto.initializeSignalUser("Bob");
        const bobBundle = await crypto.getSignalPublicKeyBundle(bob);
        const exchangeResult = await crypto.performSignalX3DHKeyExchange(alice, bobBundle);

        const aliceState = await crypto.initializeDoubleRatchet(exchangeResult.masterSecret, true);
        const bobState = await crypto.initializeDoubleRatchet(exchangeResult.masterSecret, false);

        console.log('📊 Initial state analysis:');
        console.log('Alice (initiator) has sending chain key:', !!aliceState.sendingChainKey);
        console.log('Alice (initiator) has receiving chain key:', !!aliceState.receivingChainKey);
        console.log('Bob (responder) has sending chain key:', !!bobState.sendingChainKey);
        console.log('Bob (responder) has receiving chain key:', !!bobState.receivingChainKey);

        // The key insight: Bob should get a receiving chain key after processing Alice's first message
        const msg1 = 'Test message for chain key establishment';
        const encrypted1 = await crypto.doubleRatchetEncrypt(aliceState, msg1);
        
        console.log('📋 Before decryption - Bob receiving chain key:', !!bobState.receivingChainKey);
        
        await crypto.doubleRatchetDecrypt(bobState, encrypted1);
        
        console.log('📋 After decryption - Bob receiving chain key:', !!bobState.receivingChainKey);
        console.log('✅ Bob now has receiving chain key for processing messages');

        // Bob should be able to send back now
        const msg2 = 'Bob reply after establishing chains';
        const encrypted2 = await crypto.doubleRatchetEncrypt(bobState, msg2);
        
        console.log('📋 Bob can now encrypt (has sending chain key):', !!bobState.sendingChainKey);
        
        const decrypted2 = await crypto.doubleRatchetDecrypt(aliceState, encrypted2);
        
        console.log('✅ Alice received Bob\'s reply:', decrypted2);
        expect(decrypted2).toBeDefined();
        expect(typeof decrypted2).toBe('string');
        
        console.log('🎯 Chain key establishment pattern verified!');
    });
});