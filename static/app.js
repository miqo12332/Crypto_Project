async function registerUser() {
    const name = document.getElementById("reg_name").value;
    const res = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_id: name })
    });
    alert(await res.text());
}

async function getSharedKey(a, b) {
    const res = await fetch("/shared-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_a: a, client_b: b })
    });
    const data = await res.json();
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

async function sendMessage() {
    const sender = document.getElementById("send_from").value;
    const receiver = document.getElementById("send_to").value;
    const message = document.getElementById("send_msg").value;

    const key = await getSharedKey(sender, receiver);
    const ct = await encryptMessage(key, message);

    await fetch("/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender: sender, receiver: receiver, ciphertext: ct })
    });

    alert("Message sent!");
}

async function checkInbox() {
    const user = document.getElementById("inbox_user").value;
    const res = await fetch("/inbox/" + user);
    const msgs = await res.json();

    let html = "";
    msgs.forEach(m => {
        html += `
            <div class="msg">
                <b>From:</b> ${m.from}<br>
                <b>Encrypted:</b> ${m.ciphertext}<br>
                <b>Status:</b> ${m.status}<br>
                <b>Time:</b> ${new Date(m.timestamp * 1000).toLocaleString()}
            </div>
        `;
    });
    document.getElementById("messages").innerHTML = html;
}
