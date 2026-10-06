/**
 * Common Passwords Dictionary for Offline Analysis
 * Contains top commonly leaked passwords for instant pattern & dictionary matching.
 */
const COMMON_PASSWORDS_SET = new Set([
  "123456", "password", "123456789", "12345678", "12345", "1234567", "1234", "qwerty",
  "1234567890", "111111", "abc123", "dragon", "admin", "welcome", "monkey", "password1",
  "sunshine", "football", "princess", "charlie", "123321", "iloveyou", "trustno1", "computer",
  "master", "shadow", "superman", "starwars", "batman", "pass123", "solo", "hello",
  "freedom", "whatever", "love", "mustang", "keyboard", "access", "shadow", "baseball",
  "matrix", "cyber", "system", "change", "testing", "letmein", "guest", "root",
  "qwertz", "azerty", "987654321", "654321", "123123", "666666", "7777777", "888888",
  "000000", "password123", "p@ssword", "p@ssw0rd", "pass1234", "admin123", "admin1234",
  "pass@123", "welcome1", "welcome123", "login", "user", "oracle", "cisco", "passcode",
  "1234567890a", "password01", "qwerty123", "asdfghjk", "asdf1234", "zxcvbnm", "google"
]);

// Common keyboard walk patterns
const KEYBOARD_WALKS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm",
  "1234567890", "0987654321",
  "qwertzuiop", "azertyuiop",
  "qazwsxedc", "1q2w3e4r5t"
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { COMMON_PASSWORDS_SET, KEYBOARD_WALKS };
}
