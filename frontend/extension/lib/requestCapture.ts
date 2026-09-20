/**
 * Shape of one captured request template. Only names/shapes are ever
 * captured here — never header values, cookies, tokens, or body values —
 * per the "do not send raw cookies, bearer tokens, passwords, or response
 * secrets" rule in FRONTEND_CHANGES_NEEDED.md.
 */
export interface CapturedRequest {
  url: string;
  method: string;
  contentType: string;
  queryParamNames: string[];
  bodyFieldNames: string[];
}
