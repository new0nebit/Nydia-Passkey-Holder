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
  /* Fullscreen host that centers the iframe horizontally; JS controls the top offset. */
  .nydia-frame {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: clamp(100px, calc(5vh + 85px), 200px);
    pointer-events: none;
    transition: padding-top 0.15s ease-out;
  }
  .nydia-popup-shell {
    background: white;
    border-radius: 10px;
    overflow: hidden;
    box-shadow:
      0 2.5px 7.5px rgba(15, 23, 42, 0.18),
      0 6px 11.25px rgba(15, 23, 42, 0.22);
  }
  @media (prefers-color-scheme: dark) {
    .nydia-popup-shell {
      background: #1F2937;
      box-shadow:
        0 3px 9px rgba(0, 0, 0, 0.38),
        0 7.5px 13.5px rgba(0, 0, 0, 0.52);
    }
  }
  /* Iframe hosting the popup UI */
  iframe {
    width: 380px;
    max-height: 90vh;
    border: 0;
    background: transparent;
    display: block;
    pointer-events: auto;
  }
`;
