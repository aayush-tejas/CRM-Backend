declare module 'pdf-parse' {
  type PdfBuffer = ArrayBuffer | Buffer | Uint8Array

  interface PdfParseOptions {
    pagerender?: (pageData: any) => string | Promise<string>
    version?: string
    max?: number
  }

  interface PdfParseResult {
    numpages: number
    numrender: number
    info: Record<string, unknown>
    metadata?: any
    text: string
    version: string
  }

  export default function pdfParse(buffer: PdfBuffer, options?: PdfParseOptions): Promise<PdfParseResult>
}

declare module 'pdf-parse/lib/pdf-parse.js' {
  import pdfParse from 'pdf-parse'
  export default pdfParse
}
