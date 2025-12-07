const selectors = {
    regName: document.getElementById("reg_name"),
    registerStatus: document.getElementById("register_status"),
    regOutput: document.getElementById("reg_output"),
    sharedA: document.getElementById("shared_a"),
    sharedB: document.getElementById("shared_b"),
    sharedStatus: document.getElementById("shared_status"),
    sharedOutput: document.getElementById("shared_output"),
    sendFrom: document.getElementById("send_from"),
    sendTo: document.getElementById("send_to"),
    sendMsg: document.getElementById("send_msg"),
    sendKey: document.getElementById("send_key"),
    sendCipher: document.getElementById("send_cipher"),
    sendStatus: document.getElementById("send_status"),
    inboxUser: document.getElementById("inbox_user"),
    inboxStatus: document.getElementById("inbox_status"),
    messages: document.getElementById("messages"),
};

function setBadge(el, text, type = "info") {
    el.textContent = text;
    el.className = `badge ${type}`;
}

async function refreshClientOptions() {
    const res = await fetch("/clients");
    const users = await res.json();
    [selectors.sharedA, selectors.sharedB, selectors.sendFrom, selectors.sendTo, selectors.inboxUser].forEach(sel => {
        sel.innerHTML = "";
        users.forEach(u => {
            const opt = document.createElement("option");
            opt.value = u;
            opt.textContent = u;
            sel.appendChild(opt);
        });
    });
}

async function registerUser(evt) {
    evt.preventDefault();
    setBadge(selectors.registerStatus, "Registering...", "info");
    const name = selectors.regName.value.trim();
    if (!name) return;
    const res = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_id: name })
    });
    const data = await res.json();
    if (res.ok) {
        setBadge(selectors.registerStatus, "User registered", "success");
        selectors.regOutput.textContent = JSON.stringify(data, null, 2);
        selectors.regName.value = "";
        await refreshClientOptions();
    } else {
        setBadge(selectors.registerStatus, data.error || "Failed", "error");
    }
}

async function getSharedKey(a, b) {
    const res = await fetch("/shared-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_a: a, client_b: b })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Unable to derive key");
    return data.shared_key;
}

async function encryptMessage(key, msg) {
    const res = await fetch("/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: key, message: msg })
    });
    return (await res.json()).ciphertext;
}

async function decryptMessage(key, ciphertext) {
    const res = await fetch("/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, ciphertext })
    });
    const data = await res.json();
    return data.plaintext;
}

async function deriveShared(evt) {
    evt.preventDefault();
    const a = selectors.sharedA.value;
    const b = selectors.sharedB.value;
    setBadge(selectors.sharedStatus, "Deriving...", "info");
    try {
        const key = await getSharedKey(a, b);
        selectors.sharedOutput.textContent = JSON.stringify({ users: `${a} & ${b}`, shared_key: key }, null, 2);
        setBadge(selectors.sharedStatus, "Done", "success");
    } catch (err) {
        selectors.sharedOutput.textContent = err.message;
        setBadge(selectors.sharedStatus, "Error", "error");
    }
}

async function sendMessage(evt) {
    evt.preventDefault();
    const sender = selectors.sendFrom.value;
    const receiver = selectors.sendTo.value;
    const message = selectors.sendMsg.value;
    if (!message) return;
    setBadge(selectors.sendStatus, "Encrypting...", "info");
    try {
        const key = await getSharedKey(sender, receiver);
        const ct = await encryptMessage(key, message);
        selectors.sendKey.textContent = key;
        selectors.sendCipher.textContent = ct;

        await fetch("/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sender, receiver, ciphertext: ct })
        });
        selectors.sendMsg.value = "";
        setBadge(selectors.sendStatus, "Sent securely", "success");
    } catch (err) {
        setBadge(selectors.sendStatus, err.message, "error");
    }
}

function renderMessageCard(msg, plaintext) {
    const el = document.createElement("div");
    el.className = "msg";
    el.innerHTML = `
        <div class="meta">
            <div><strong>From:</strong> ${msg.from}</div>
            <div class="pill">${msg.status}</div>
            <div class="timestamp">${new Date(msg.timestamp * 1000).toLocaleString()}</div>
        </div>
        <div class="payloads">
            <div>
                <p class="hint">Encrypted payload</p>
                <pre class="code">${msg.ciphertext}</pre>
            </div>
            <div>
                <p class="hint">Decrypted text</p>
                <pre class="code highlight">${plaintext}</pre>
            </div>
        </div>
    `;
    return el;
}

async function checkInbox(evt) {
    if (evt) evt.preventDefault();
    const user = selectors.inboxUser.value;
    setBadge(selectors.inboxStatus, "Loading inbox...", "info");
    const res = await fetch(`/inbox/${user}`);
    const msgs = await res.json();
    selectors.messages.innerHTML = "";
    for (const m of msgs) {
        try {
            const key = await getSharedKey(user, m.from);
            const plain = await decryptMessage(key, m.ciphertext);
            selectors.messages.appendChild(renderMessageCard(m, plain));
        } catch (err) {
            selectors.messages.appendChild(renderMessageCard(m, `Error: ${err.message}`));
        }
    }
    if (msgs.length === 0) {
        selectors.messages.innerHTML = '<div class="empty">No messages yet.</div>';
    }
    setBadge(selectors.inboxStatus, `Loaded ${msgs.length} message(s)`, "success");
}

function wireEvents() {
    document.getElementById("register_form").addEventListener("submit", registerUser);
    document.getElementById("shared_form").addEventListener("submit", deriveShared);
    document.getElementById("send_form").addEventListener("submit", sendMessage);
    document.getElementById("inbox_refresh").addEventListener("click", checkInbox);
}

async function bootstrap() {
    await refreshClientOptions();
    wireEvents();
    setBadge(selectors.inboxStatus, "Ready", "info");
}

bootstrap();
