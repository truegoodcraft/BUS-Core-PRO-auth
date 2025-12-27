export const sendMagicCode = async (
  apiKey: string,
  from: string,
  to: string,
  code: string
): Promise<boolean> => {
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [to],
        subject: "Your BUS Core Login Code",
        html: `<p>Your login code is: <strong>${code}</strong></p><p>Expires in 15 minutes.</p>`,
      }),
    });

    return response.ok;
  } catch (error) {
    console.error("Failed to send magic code email", error);
    return false;
  }
};
