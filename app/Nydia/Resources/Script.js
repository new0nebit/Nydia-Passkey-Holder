function useSettingsInsteadOfPreferences() {
    document.getElementsByClassName('state-on')[0].innerText = "Nydia’s extension is currently on. You can turn it off in the Extensions section of Safari Settings.";
    document.getElementsByClassName('state-off')[0].innerText = "Nydia’s extension is currently off. You can turn it on in the Extensions section of Safari Settings.";
    document.getElementsByClassName('state-unknown')[0].innerText = "You can turn on Nydia’s extension in the Extensions section of Safari Settings.";
    document.getElementsByClassName('open-preferences')[0].innerText = "Quit and Open Safari Settings…";
    document.getElementsByClassName('error-hint')[0].innerText = "To turn on Nydia manually, open Safari and choose Safari > Settings > Extensions.";
}

function show(enabled) {
    if (typeof enabled === "boolean") {
        document.body.classList.toggle(`state-on`, enabled);
        document.body.classList.toggle(`state-off`, !enabled);
    } else {
        document.body.classList.remove(`state-on`);
        document.body.classList.remove(`state-off`);
    }
}

// Appends rather than replaces, so a failed fallback does not hide the failure that triggered it.
function showError(action, code) {
    const line = document.createElement("div");
    line.textContent = code ? `Couldn’t ${action} (${code}).` : `Couldn’t ${action}.`;
    document.querySelector(".error-details").append(line);
    document.querySelector(".error").hidden = false;
}

function openPreferences() {
    webkit.messageHandlers.controller.postMessage("open-preferences");
}

document.querySelector("button.open-preferences").addEventListener("click", openPreferences);
