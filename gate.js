(() => {
  const STORE = "fuse.siteKey";
  const form = document.getElementById("gate");
  const input = document.getElementById("gate-password");
  const remember = document.getElementById("gate-remember");
  const button = document.getElementById("gate-open");
  const message = document.getElementById("gate-message");
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const toB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
  // Invite links carry the key in a form that survives being part of an address.
  const toB64Url = (b) => toB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const fromB64Url = (s) => fromB64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  let locked;

  async function lockedFile() {
    if (!locked) locked = fetch("./app.lock", { cache: "no-cache" }).then((r) => {
      if (!r.ok) throw new Error("missing");
      // Which version this is, so the app can tell when a newer one is published.
      window.__fuseBuild = r.headers.get("ETag") || r.headers.get("Last-Modified") || "";
      return r.json();
    });
    return locked;
  }

  async function run(key, file) {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(file.iv) }, key, fromB64(file.data));
    // The app puts this key in the invite links it makes, so the people invited can open the site too.
    window.__fuseSiteKey = toB64Url(await crypto.subtle.exportKey("raw", key));
    // The app finds its other files relative to where it would normally live.
    const home = JSON.stringify(new URL("./assets/index-pDjoG6-L.js", location.href).href);
    const code = new TextDecoder().decode(plain).split("import.meta.url").join(home);
    const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
    form.remove();
    await import(url);
  }

  async function keyFromPassword(password, file) {
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: fromB64(file.salt), iterations: file.iterations, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.textContent = "";
    button.disabled = true;
    button.textContent = "Unlocking…";
    try {
      const file = await lockedFile();
      const key = await keyFromPassword(input.value, file);
      try {
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(file.iv) }, key, fromB64(file.data));
      } catch {
        message.textContent = "That password isn't right.";
        input.select();
        return;
      }
      if (remember.checked) {
        try { localStorage.setItem(STORE, JSON.stringify({ salt: file.salt, key: toB64(await crypto.subtle.exportKey("raw", key)) })); } catch {}
      }
      await run(key, file);
    } catch {
      message.textContent = "The site couldn't be unlocked. Check your connection and try again.";
    } finally {
      button.disabled = false;
      button.textContent = "Unlock";
    }
  });

  // An invite link carries the key after "k=" in its #fragment, which never reaches the server. It is
  // taken out of the address straight away, so it isn't kept in the history or a bookmark. This tab
  // keeps it until it's closed, so reloading the page still opens the site.
  const TAB = "fuse.siteKey.tab";
  function keyFromLink() {
    const params = new URLSearchParams(location.hash.slice(1));
    const k = params.get("k");
    if (!k) {
      try { return sessionStorage.getItem(TAB); } catch { return null; }
    }
    params.delete("k");
    const rest = params.toString();
    history.replaceState(null, "", location.pathname + location.search + (rest ? "#" + rest : ""));
    return k;
  }

  // A link's key opens the site; otherwise a device that was told to remember skips the password,
  // until the site is republished.
  (async () => {
    const linked = keyFromLink();
    // The password box takes the focus, except inside another site's frame (an embedded signing link), where browsers refuse.
    if (!linked && window.parent === window) document.getElementById("gate-password")?.focus();
    if (linked) {
      try {
        const file = await lockedFile();
        const key = await crypto.subtle.importKey("raw", fromB64Url(linked), "AES-GCM", true, ["decrypt"]);
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(file.iv) }, key, fromB64(file.data));
        try { sessionStorage.setItem(TAB, linked); } catch {}
        await run(key, file);
        return;
      } catch {
        try { sessionStorage.removeItem(TAB); } catch {}
        message.textContent = "This invite link doesn't open the site any more. Enter the password, or ask for a new link.";
      }
    }
    let saved;
    try { saved = JSON.parse(localStorage.getItem(STORE) || "null"); } catch {}
    if (!saved) return;
    try {
      const file = await lockedFile();
      if (file.salt !== saved.salt) { localStorage.removeItem(STORE); return; }
      const key = await crypto.subtle.importKey("raw", fromB64(saved.key), "AES-GCM", true, ["decrypt"]);
      await run(key, file);
      message.textContent = "";
    } catch {
      try { localStorage.removeItem(STORE); } catch {}
    }
  })();
})();
