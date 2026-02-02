/**
 * Sample Test - Infrastructure Validation
 * This test verifies that Jest and TypeScript are configured correctly
 */

describe('Infrastructure Setup', () => {
  it('should run Jest tests successfully', () => {
    expect(1 + 1).toBe(2);
  });

  it('should support TypeScript', () => {
    const sum = (a: number, b: number): number => a + b;
    expect(sum(2, 3)).toBe(5);
  });

  it('should have test environment configured', () => {
    expect(process.env['NODE_ENV']).toBe('test');
  });
});
