/** Renders a self-contained page as a string. */
export declare function renderOfflineVerifier(): Promise<string>;
export declare function renderPage(page: Page): Promise<string>;
export type Page = {
  name: string;
  entry: string;
  template: string;
  out: string;
  verifies: boolean;
};
export declare const PAGES: Page[];
