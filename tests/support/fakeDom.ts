type Listener = (event: FakeEvent) => void;

export class FakeEvent {
  public currentTarget: FakeElement | null = null;
  public propagationStopped = false;

  public constructor(
    public readonly type: string,
    public target: FakeElement | null = null
  ) {}

  public stopPropagation(): void {
    this.propagationStopped = true;
  }
}

class FakeClassList {
  private readonly values = new Set<string>();

  public constructor(private readonly owner: FakeElement) {}

  public add(...tokens: string[]): void {
    for (const token of tokens) {
      if (token.trim()) {
        this.values.add(token.trim());
      }
    }
    this.sync();
  }

  public remove(...tokens: string[]): void {
    for (const token of tokens) {
      this.values.delete(token.trim());
    }
    this.sync();
  }

  public contains(token: string): boolean {
    return this.values.has(token.trim());
  }

  public replaceFromClassName(className: string): void {
    this.values.clear();
    for (const token of className.split(/\s+/).filter(Boolean)) {
      this.values.add(token);
    }
    this.sync();
  }

  public toString(): string {
    return Array.from(this.values).join(' ');
  }

  private sync(): void {
    this.owner.classNameValue = Array.from(this.values).join(' ');
  }
}

class FakeNodeCollection<T extends FakeElement> extends Array<T> {
  public item(index: number): T | null {
    return this[index] ?? null;
  }
}

export class FakeElement {
  public attributes = new Map<string, string>();
  public checked = false;
  public classList = new FakeClassList(this);
  public classNameValue = '';
  public clientHeight = 120;
  public colSpan = 1;
  public dataset: Record<string, string> = {};
  public disabled = false;
  public listeners = new Map<string, Listener[]>();
  public parentElement: FakeElement | null = null;
  public placeholder = '';
  public scrollTop = 0;
  public style: Record<string, string> = {};
  public type = '';
  public value = '';

  protected childNodes: FakeElement[] = [];
  protected textContentValue = '';

  public constructor(public readonly tagName: string) {}

  public get children(): FakeElement[] {
    return [...this.childNodes];
  }

  public get className(): string {
    return this.classNameValue;
  }

  public set className(value: string) {
    this.classList.replaceFromClassName(value);
  }

  public get firstElementChild(): FakeElement | null {
    return this.childNodes[0] ?? null;
  }

  public get scrollHeight(): number {
    return Math.max(this.childNodes.length * 40, 120);
  }

  public get textContent(): string {
    if (this.childNodes.length === 0) {
      return this.textContentValue;
    }

    return this.textContentValue + this.childNodes.map((child) => child.textContent).join('');
  }

  public set textContent(value: string) {
    this.textContentValue = value;
    this.childNodes = [];
  }

  public addClass(...tokens: string[]): void {
    this.classList.add(...tokens);
  }

  public addEventListener(type: string, listener: Listener): void {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  public append(...nodes: FakeElement[]): void {
    for (const node of nodes) {
      this.appendChild(node);
    }
  }

  public appendChild<T extends FakeElement>(node: T): T {
    node.remove();
    node.parentElement = this;
    this.childNodes.push(node);
    return node;
  }

  public appendText(text: string): void {
    this.textContentValue += text;
  }

  public click(): void {
    this.dispatchEvent(new FakeEvent('click', this));
  }

  public closest(selector: string): FakeElement | null {
    let current: FakeElement | null = this;
    while (current) {
      if (current.matches(selector)) {
        return current;
      }
      current = current.parentElement;
    }
    return null;
  }

  public createDiv(options?: { cls?: string; text?: string }): FakeDivElement {
    return this.createEl('div', options) as FakeDivElement;
  }

  public createEl(
    tagName: string,
    options?: {
      attr?: Record<string, string>;
      cls?: string;
      text?: string;
      value?: string;
    }
  ): FakeElement {
    const element = fakeDocument.createElement(tagName);
    if (options?.cls) {
      element.className = options.cls;
    }
    if (options?.text !== undefined) {
      element.textContent = options.text;
    }
    if (options?.value !== undefined) {
      element.value = options.value;
    }
    for (const [key, value] of Object.entries(options?.attr ?? {})) {
      element.setAttribute(key, value);
      if (key === 'type') {
        element.type = value;
      }
      if (key === 'placeholder') {
        element.placeholder = value;
      }
    }
    this.appendChild(element);
    return element;
  }

  public createSpan(options?: { cls?: string; text?: string }): FakeElement {
    return this.createEl('span', options);
  }

  public dispatchEvent(event: FakeEvent): void {
    event.target ??= this;
    event.currentTarget = this;
    for (const listener of this.listeners.get(event.type) ?? []) {
      listener(event);
      if (event.propagationStopped) {
        return;
      }
    }
  }

  public empty(): void {
    for (const child of this.childNodes) {
      child.parentElement = null;
    }
    this.childNodes = [];
    this.textContentValue = '';
  }

  public matches(selector: string): boolean {
    if (selector.startsWith('.')) {
      return this.classList.contains(selector.slice(1));
    }

    const dataMatch = selector.match(/^\[data-([^=]+)="([^"]+)"\]$/);
    if (dataMatch) {
      const rawKey = dataMatch[1];
      const expected = dataMatch[2];
      if (!rawKey || !expected) {
        return false;
      }
      const datasetKey = rawKey.replace(/-([a-z])/g, (_, letter: string) => letter.toUpperCase());
      return this.dataset[datasetKey] === expected;
    }

    return this.tagName.toLowerCase() === selector.toLowerCase();
  }

  public querySelector<T extends FakeElement = FakeElement>(selector: string): T | null {
    if (selector.startsWith(':scope > ')) {
      const childSelector = selector.slice(':scope > '.length);
      for (const child of this.childNodes) {
        if (child.matches(childSelector)) {
          return child as T;
        }
      }
      return null;
    }

    for (const child of this.childNodes) {
      if (child.matches(selector)) {
        return child as T;
      }
      const nested = child.querySelector<T>(selector);
      if (nested) {
        return nested;
      }
    }
    return null;
  }

  public querySelectorAll<T extends FakeElement = FakeElement>(selector: string): FakeNodeCollection<T> {
    const matches = new FakeNodeCollection<T>();
    for (const child of this.childNodes) {
      if (child.matches(selector)) {
        matches.push(child as T);
      }
      matches.push(...child.querySelectorAll<T>(selector));
    }
    return matches;
  }

  public remove(): void {
    if (!this.parentElement) {
      return;
    }

    this.parentElement.childNodes = this.parentElement.childNodes.filter((child) => child !== this);
    this.parentElement = null;
  }

  public removeClass(...tokens: string[]): void {
    this.classList.remove(...tokens);
  }

  public replaceChildren(...nodes: FakeElement[]): void {
    this.empty();
    this.append(...nodes);
  }

  public setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  public setText(text: string): void {
    this.textContent = text;
  }
}

export class FakeDivElement extends FakeElement {
  public constructor() {
    super('div');
  }
}

export class FakeInputElement extends FakeElement {
  public constructor() {
    super('input');
  }
}

export class FakeOptionElement extends FakeElement {
  public selected = false;

  public constructor() {
    super('option');
  }
}

export class FakeSelectElement extends FakeElement {
  public constructor() {
    super('select');
  }
}

export class FakeTableCellElement extends FakeElement {
  public constructor(tagName = 'td') {
    super(tagName);
  }
}

export class FakeTableRowElement extends FakeElement {
  public constructor() {
    super('tr');
  }

  public get cells(): FakeNodeCollection<FakeTableCellElement> {
    const cells = new FakeNodeCollection<FakeTableCellElement>();
    for (const child of this.children) {
      if (child instanceof FakeTableCellElement) {
        cells.push(child);
      }
    }
    return cells;
  }
}

export class FakeTableSectionElement extends FakeElement {
  public constructor(tagName: 'thead' | 'tbody') {
    super(tagName);
  }

  public get rows(): FakeNodeCollection<FakeTableRowElement> {
    const rows = new FakeNodeCollection<FakeTableRowElement>();
    for (const child of this.children) {
      if (child instanceof FakeTableRowElement) {
        rows.push(child);
      }
    }
    return rows;
  }
}

export class FakeDocument {
  public body = new FakeDivElement();

  public createElement(tagName: string): FakeElement {
    switch (tagName.toLowerCase()) {
      case 'button':
        return new FakeElement('button');
      case 'div':
        return new FakeDivElement();
      case 'input':
        return new FakeInputElement();
      case 'label':
        return new FakeElement('label');
      case 'option':
        return new FakeOptionElement();
      case 'p':
        return new FakeElement('p');
      case 'search':
        return new FakeInputElement();
      case 'select':
        return new FakeSelectElement();
      case 'span':
        return new FakeElement('span');
      case 'strong':
        return new FakeElement('strong');
      case 'table':
        return new FakeElement('table');
      case 'tbody':
        return new FakeTableSectionElement('tbody');
      case 'td':
        return new FakeTableCellElement('td');
      case 'th':
        return new FakeTableCellElement('th');
      case 'thead':
        return new FakeTableSectionElement('thead');
      case 'tr':
        return new FakeTableRowElement();
      default:
        return new FakeElement(tagName);
    }
  }
}

const fakeDocument = new FakeDocument();

export const installFakeDom = (): FakeDocument => {
  globalThis.document = fakeDocument as unknown as Document;
  globalThis.window = { document: fakeDocument } as unknown as Window & typeof globalThis;
  globalThis.HTMLElement = FakeElement as unknown as typeof HTMLElement;
  globalThis.HTMLDivElement = FakeDivElement as unknown as typeof HTMLDivElement;
  globalThis.HTMLInputElement = FakeInputElement as unknown as typeof HTMLInputElement;
  globalThis.HTMLSelectElement = FakeSelectElement as unknown as typeof HTMLSelectElement;
  globalThis.HTMLTableCellElement = FakeTableCellElement as unknown as typeof HTMLTableCellElement;
  globalThis.HTMLTableRowElement = FakeTableRowElement as unknown as typeof HTMLTableRowElement;
  globalThis.HTMLTableSectionElement = FakeTableSectionElement as unknown as typeof HTMLTableSectionElement;
  return fakeDocument;
};

export const createRoot = (): FakeDivElement => new FakeDivElement();
