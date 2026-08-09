/** Renders a self-contained page as a string. */
export declare function renderOfflineVerifier(): Promise<string>;
export declare function renderPage(page: {
  name: string;
  entry: string;
  template: string;
  out: string;
}): Promise<string>;
export declare const PAGES: { name: string; entry: string; template: string; out: string }[];
