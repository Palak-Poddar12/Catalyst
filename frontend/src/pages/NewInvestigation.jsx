async function run() {
  if (!file) return;

  setBusy(true);
  setErr(null);

  try {
    const c = await createCase({
      title: "New Email Investigation",
    });

    const result = await uploadEmail(c.id, file);

    setResult(result);

    nav(`/cases/${c.id}`);
  } catch (e) {
    setErr(e.message || "Email analysis failed.");
  } finally {
    setBusy(false);
  }
}
