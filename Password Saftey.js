import zxcvbn from "zxcvbn";

function generateRandomPassword(length = 16) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
  let password = "";
  for (let i = 0; i < length; i++) {
    password += chars[Math.floor(Math.random() * chars.length)];
  }
  return password;
}

export async function checkPassword(password) {
  const result = zxcvbn(password);
  const strengthScore = result.score;
  const strengthLabel = ["Weak", "Weak", "Fair", "Moderate", "Strong"][strengthScore];

  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();

  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await res.text();

  let breachCount = 0;
  const lines = text.split("\n");
  for (const line of lines) {
    const [hashSuffix, count] = line.split(":");
    if (hashSuffix === suffix) {
      breachCount = parseInt(count, 10);
      break;
    }
  }

  let suggestedPassword = null;
  if (strengthScore < 3) {
    do {
      suggestedPassword = generateRandomPassword();
    } while (zxcvbn(suggestedPassword).score < 3);
  }

  return {
    strengthScore,
    strengthLabel,
    breachCount,
    breached: breachCount > 0,
    suggestedPassword
  };
}
