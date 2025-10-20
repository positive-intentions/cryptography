/**
 * Mock MLS Manager for Jest tests
 * This mock avoids ES module import issues with ts-mls during testing
 */

export class MLSManager {
  constructor() {
    this.groups = new Map();
  }

  async createGroup(groupId) {
    const mockGroup = {
      groupId,
      members: [],
      epochId: 0
    };
    this.groups.set(groupId, mockGroup);
    return mockGroup;
  }

  async addMember(groupId, memberId) {
    const group = this.groups.get(groupId);
    if (group) {
      group.members.push(memberId);
    }
    return group;
  }

  async encryptMessage(groupId, message) {
    return `encrypted:${message}`;
  }

  async decryptMessage(groupId, encryptedMessage) {
    return encryptedMessage.replace('encrypted:', '');
  }

  getGroup(groupId) {
    return this.groups.get(groupId);
  }
}

export default MLSManager;
