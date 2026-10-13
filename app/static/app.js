let token = localStorage.getItem("token");

function message(text) {
    document.getElementById("message").textContent = text;
}

async function api(path, body) {
    const response = await fetch(path, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.detail || "Ошибка запроса");
    }

    return data;
}

async function gql(query, variables = {}) {
    const response = await fetch("/graphql/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
        },
        body: JSON.stringify({ query, variables })
    });

    const result = await response.json();

    if (result.errors) {
        throw new Error(result.errors[0].message);
    }

    return result.data;
}

async function login() {
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
        const data = await api("/auth/login", {
            email,
            password
        });

        token = data.access_token;
        localStorage.setItem("token", token);

        await showPanel();
    } catch (error) {
        message(error.message);
    }
}

async function showPanel() {
    try {
        const data = await gql("{ me { isAdmin } }");

        if (!data.me.isAdmin) {
            throw new Error("Требуются права администратора");
        }

        document.getElementById("login").style.display = "none";
        document.getElementById("panel").style.display = "block";

        message("");
        await loadClients();
    } catch (error) {
        logout();
        message(error.message);
    }
}

async function loadClients() {
    try {
        const data = await gql(`
            {
                clients {
                    id
                    name
                    isConfidential
                }
            }
        `);

        const table = document.getElementById("clients");
        table.replaceChildren();

        data.clients.forEach(client => {
            const row = document.createElement("tr");

            [client.id, client.name,
             client.isConfidential ? "Да" : "Нет"].forEach(value => {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            });

            table.appendChild(row);
        });
    } catch (error) {
        message(error.message);
    }
}

async function createClient() {
    const name = document.getElementById("clientName").value.trim();

    if (!name) {
        message("Введите название клиента");
        return;
    }

    try {
        await gql(`
            mutation($name: String!) {
                createClient(name: $name, isConfidential: false) {
                    id
                    name
                }
            }
        `, { name });

        document.getElementById("clientName").value = "";
        message("Клиент создан");

        await loadClients();
    } catch (error) {
        message(error.message);
    }
}

function logout() {
    token = null;
    localStorage.removeItem("token");

    document.getElementById("login").style.display = "block";
    document.getElementById("panel").style.display = "none";
}

if (token) {
    showPanel();
}