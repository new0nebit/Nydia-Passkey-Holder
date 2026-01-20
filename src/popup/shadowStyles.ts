export const shadowStyles = `
  /* Host element injected into the page */
  :host {
    all: initial;
    position: fixed;
    inset: 0;
    z-index: 2147483647;
    display: block;
  }
  /* Dimmed backdrop behind the popup */
  .nydia-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
  }
  /* Centers the iframe without blocking pointer events */
  .nydia-frame {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: clamp(32px, 5vh, 120px);
    pointer-events: none;
  }
  /* Iframe hosting the popup UI */
  iframe {
    width: 400px;
    height: 640px;
    max-height: 90vh;
    border: 0;
    background: transparent;
    display: block;
    pointer-events: auto;
  }
`;
