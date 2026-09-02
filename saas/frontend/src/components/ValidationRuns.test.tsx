import { expect, test, describe } from 'vitest';
import { formatValidationDate } from './ValidationRuns';

describe('formatValidationDate', () => {
  test('parses naive UTC timestamp correctly', () => {
    // 2026-09-02T17:18:20 (naive UTC from backend)
    // Should be parsed as UTC and formatted to the test runner's local timezone
    // We can test this by checking that it produces a valid string that Intl.DateTimeFormat can handle
    const naiveDate = '2026-09-02T17:18:20';
    const formatted = formatValidationDate(naiveDate);
    
    // The exact string depends on the runner's timezone, but it shouldn't throw an Invalid Date error
    expect(formatted).not.toBe('Invalid Date');
    expect(formatted.length).toBeGreaterThan(0);
    
    // Let's explicitly test the parsing logic with a specific timezone (UTC) to verify output consistency
    const d = new Date(naiveDate + 'Z');
    
    const ourFormatter = new Intl.DateTimeFormat('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    
    // Ensure our function's output matches standard formatting for that parsed UTC Date
    expect(formatted).toBe(ourFormatter.format(d));
  });

  test('parses aware UTC timestamp correctly', () => {
    // If backend ever adds Z, it should still work
    const awareDate = '2026-09-02T17:18:20Z';
    const formatted = formatValidationDate(awareDate);
    
    const d = new Date(awareDate);
    const ourFormatter = new Intl.DateTimeFormat('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    
    expect(formatted).toBe(ourFormatter.format(d));
  });
});
