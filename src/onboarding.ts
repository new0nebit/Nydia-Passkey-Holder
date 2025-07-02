import browser from 'browser-api';

import { logError } from './logger';
import './styles/onboarding.css';

export class OnboardingController {
  private step = 0;
  private container: HTMLElement;
  private seedPhrase = '';
  private inputSeedPhrase = '';
  private isRecovery = false;
  private derivedKey: CryptoKey | null = null;

  constructor(root: HTMLElement) {
    this.container = root;
    this.render();
  }

  private render(): void {
    const screen = div('onboarding-container');
    const content = div('content-wrapper');

    switch (this.step) {
      case 0:
        content.append(this.viewWelcome());
        break;
      case 1:
        content.append(this.viewChoosePath());
        break;
      case 2:
        if (this.isRecovery) {
          content.append(this.viewInputSeed());
        } else {
          if (!this.seedPhrase) {
            void this.generateSeedPhrase()
              .then((s) => {
                this.seedPhrase = s;
                this.render();
              })
              .catch((e) => logError('seed gen error', e));
            break;
          }
          content.append(this.viewShowSeed());
        }
        break;
      case 6:
        content.append(this.viewSuccess());
        break;
    }

    screen.append(content);
    this.container.innerHTML = '';
    this.container.append(screen);
  }

  private viewWelcome(): HTMLElement {
    const wrap = div('flex-col');
    wrap.append(
      span('Nydia', 'logo'),
      span('Secure your passkeys with seed-based encryption', 'description'),
      button('Get Started', 'btn', () => {
        this.step = 1;
        this.render();
      }),
    );
    return wrap;
  }

  private viewChoosePath(): HTMLElement {
    const wrap = div('flex-col');
    wrap.append(
      span('Choose an Option', 'title'),
      span('Generate a new seed phrase or restore from an existing one', 'subtitle'),
      button('Generate Seed', 'btn', () => {
        this.isRecovery = false;
        this.seedPhrase = '';
        this.step = 2;
        this.render();
      }),
      button('Restore Seed', 'btn btn-secondary', () => {
        this.isRecovery = true;
        this.step = 2;
        this.render();
      }),
    );
    return wrap;
  }

  private viewShowSeed(): HTMLElement {
    const wrap = div('flex-col');
    wrap.append(
      span('Your Recovery Seed Phrase', 'title'),
      span('Write down these 12 words. They are the ONLY way to recover your passkeys.', 'subtitle'),
    );

    const grid = div('seed-grid');
    this.seedPhrase.split(' ').forEach((w, i) => {
      const cell = div('seed-word');
      cell.append(span(`${i + 1}.`, 'word-number'), span(w, 'word'));
      grid.append(cell);
    });

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'checkbox';

    const next = button('Continue', 'btn', () => void this.confirmSeedStored());
    next.disabled = true;
    cb.onchange = () => (next.disabled = !cb.checked);

    const cbWrap = div('checkbox-wrapper');
    cbWrap.append(cb, span('I have safely stored the seed phrase'));

    wrap.append(grid, cbWrap, next);
    return wrap;
  }

  private viewInputSeed(): HTMLElement {
    const wrap = div('flex-col');
    wrap.append(
      span('Enter Your Recovery Phrase', 'title'),
      span('Enter the 12 words separated by spaces', 'subtitle'),
    );

    const ta = document.createElement('textarea');
    ta.className = 'seed-input';
    ta.oninput = (e) => (this.inputSeedPhrase = (e.target as HTMLTextAreaElement).value);

    const err = div('error-message hidden');

    wrap.append(
      ta,
      err,
      button('Verify', 'btn', () => void this.verifySeed(err)),
      button('Back', 'btn btn-secondary', () => {
        this.step = 1;
        this.render();
      }),
    );
    return wrap;
  }

  private viewSuccess(): HTMLElement {
    const wrap = div('flex-col');
    
    if (this.isRecovery) {
      wrap.append(
        this.svgCheck(),
        span('Done!', 'title'),
        span('Your encryption key has been successfully recovered.', 'subtitle'),
        span('You can now start using Nydia.', 'info-text'),
        button('Start Using Nydia', 'btn', () => {
          localStorage.setItem('nydiaOnboardingDone', 'true');
          this.purgeSensitiveData();
          window.location.reload();
        }),
      );
    } else {
      wrap.append(
        this.svgCheck(),
        span('Done!', 'title'),
        span('Setup complete! You can now start using Nydia.', 'subtitle'),
        button('Start Using Nydia', 'btn', () => {
          localStorage.setItem('nydiaOnboardingDone', 'true');
          this.purgeSensitiveData();
          window.location.reload();
        }),
      );
    }
    
    return wrap;
  }

  private async confirmSeedStored(): Promise<void> {
    await this.deriveAndStoreKey(this.seedPhrase);
  }

  private async verifySeed(errBox: HTMLElement): Promise<void> {
    const res = this.validateSeedPhrase(this.inputSeedPhrase);
    if (!res.valid) {
      errBox.textContent = res.errors.join('. ');
      errBox.classList.remove('hidden');
      return;
    }
    await this.deriveAndStoreKey(this.inputSeedPhrase.trim().toLowerCase());
  }

  // Secure key transfer using RSA-OAEP
  private async secureKeyTransfer(derivedKey: CryptoKey): Promise<void> {
    let publicKeyBuffer: Uint8Array | null = null;
    let wrappedKeyBuffer: ArrayBuffer | null = null;

    try {
      // Step 1: Request public key from background
      const publicKeyResponse = await browser.runtime.sendMessage({
        type: 'getWrappingPublicKey',
      });

      if (publicKeyResponse.error) {
        throw new Error(publicKeyResponse.error);
      }

      // Step 2: Import the public key
      publicKeyBuffer = new Uint8Array(publicKeyResponse.publicKey);
      const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256',
        },
        false, // not extractable
        ['wrapKey'],
      );

      // Step 3: Wrap derived key with the public key
      wrappedKeyBuffer = await crypto.subtle.wrapKey('raw', derivedKey, publicKey, {
        name: 'RSA-OAEP',
      });

      // Step 4: Send wrapped key to background
      const storeResponse = await browser.runtime.sendMessage({
        type: 'storeWrappedKey',
        wrappedKey: Array.from(new Uint8Array(wrappedKeyBuffer)),
      });

      if (storeResponse.error) {
        throw new Error(storeResponse.error);
      }
    } finally {
      // Clean up all sensitive data
      if (publicKeyBuffer) {
        this.secureCleanup(publicKeyBuffer);
      }
      if (wrappedKeyBuffer) {
        this.secureCleanup(new Uint8Array(wrappedKeyBuffer));
      }
    }
  }

  // Secure cleanup of sensitive data
  private secureCleanup(data: Uint8Array): void {
    crypto.getRandomValues(data);
    data.fill(0);
  }

  private async deriveAndStoreKey(seed: string): Promise<void> {
    try {
      // Derive key from seed
      this.derivedKey = await this.deriveKeyFromSeed(seed);

      // Use secure transfer instead of raw export
      await this.secureKeyTransfer(this.derivedKey);

      // Move to success step
      this.step = 6;
      this.render();
    } catch (error) {
      logError('Failed to securely store key', error);

      // Show error to user
      const errorEl = document.querySelector('.error-message');
      if (errorEl) {
        errorEl.textContent = 'Failed to secure your key. Please try again.';
        errorEl.classList.remove('hidden');
      }
    }
  }

  private async deriveKeyFromSeed(seed: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(seed), 'PBKDF2', false, [
      'deriveKey',
    ]);
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: enc.encode('NydiaSeedOnlySalt'),
        iterations: 666_000,
        hash: 'SHA-256',
      },
      base,
      { name: 'AES-GCM', length: 256 },
      true, // Must be extractable for wrapping
      ['encrypt', 'decrypt'],
    );
  }

  private async generateSeedPhrase(): Promise<string> {
    const entropy = new Uint8Array(16);
    crypto.getRandomValues(entropy);

    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy));
    const checksum4 = (hash[0] & 0xf0) >> 4;

    const hi = this.u64(entropy, 0);
    const lo = this.u64(entropy, 8);
    const lastIdx = Number(((lo & 0x7fn) << 4n) | BigInt(checksum4));

    let l = (lo >> 7n) | (hi << 57n);
    let h = hi >> 7n;

    const words = new Array<string>(12);
    words[11] = bip39EnglishWordList[lastIdx];

    for (let i = 10; i >= 0; --i) {
      const idx = Number(l & 0x7ffn);
      words[i] = bip39EnglishWordList[idx];
      l = (l >> 11n) | (h << 53n);
      h >>= 11n;
    }

    // Clean up sensitive data
    this.secureCleanup(entropy);
    this.secureCleanup(hash);

    return words.join(' ');
  }

  private validateSeedPhrase(txt: string): { valid: boolean; errors: string[] } {
    const words = txt.trim().toLowerCase().split(/\s+/);
    const errors: string[] = [];
    if (words.length !== 12) errors.push(`Exactly 12 words required (got ${words.length})`);
    const bad = words.filter((w) => !bip39EnglishWordList.includes(w));
    if (bad.length) errors.push(`Words not in dictionary: ${bad.join(', ')}`);
    return { valid: errors.length === 0, errors };
  }

  // misc helpers
  private svgCheck(): HTMLElement {
    const wrap = div('success-icon');
    wrap.innerHTML =
      '<svg class="w-8 h-8 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
      '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
    return wrap;
  }

  private purgeSensitiveData(): void {
    this.derivedKey = null;

    // Secure cleanup of seed phrases
    if (this.seedPhrase) {
      const seedArray = new TextEncoder().encode(this.seedPhrase);
      this.secureCleanup(seedArray);
      this.seedPhrase = '';
    }

    if (this.inputSeedPhrase) {
      const inputArray = new TextEncoder().encode(this.inputSeedPhrase);
      this.secureCleanup(inputArray);
      this.inputSeedPhrase = '';
    }
  }

  private u64(buf: Uint8Array, off: number): bigint {
    let x = 0n;
    for (let i = 0; i < 8; i++) {
      x = (x << 8n) | BigInt(buf[off + i]);
    }
    return x;
  }
}

// DOM helpers
function div(cls: string): HTMLDivElement {
  const d = document.createElement('div');
  d.className = cls;
  return d;
}

function span(text: string, cls = ''): HTMLSpanElement {
  const s = document.createElement('span');
  if (cls) s.className = cls;
  s.textContent = text;
  return s;
}

function button(label: string, cls: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement('button');
  b.className = cls;
  b.textContent = label;
  b.onclick = onClick;
  return b;
}

const bip39EnglishWordList = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
  "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
  "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle",
  "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic",
  "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
  "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future",
  "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit",
  "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid",
  "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
  "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just",
  "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
  "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics",
  "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth",
  "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut",
  "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone",
  "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid",
  "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote",
  "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural",
  "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
  "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
  "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility",
  "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage",
  "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong",
  "yard", "year", "yellow", "you", "young", "youth",
  "zebra", "zero", "zone", "zoo"
];
