(function() {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('webauthn.js');
    script.onload = function() {
        this.remove();
    };
    (document.head || document.documentElement).appendChild(script);
})();
