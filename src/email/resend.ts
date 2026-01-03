export type EmailEnv = {
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
};

export async function sendMagicEmail(
  env: EmailEnv,
  to: string,
  subject: string,
  text: string
): Promise<void> {
  const apiKey = env.RESEND_API_KEY;
  const from = env.EMAIL_FROM;

  if (!apiKey || !from) {
    throw new Error("email_not_configured");
  }

  const payload = { from, to, subject, text };

  console.log("[email] resend request", { to, from, subject });
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const body = await r.text();
  console.log("[email] resend response", {
    status: r.status,
    body: body.slice(0, 256),
  });

  if (!r.ok) {
    throw new Error(`resend_failed_${r.status}`);
  }
}
