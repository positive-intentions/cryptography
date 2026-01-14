/**
 * Storybook Test Runner Configuration
 *
 * Configures Storybook test runner for ML-KEM and other crypto stories.
 */

module.exports = {
  async postVisit(page, context) {
    await page.waitForTimeout(100);
  },

  timeout: 60000,
};
