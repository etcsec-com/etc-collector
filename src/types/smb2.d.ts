/**
 * Type declarations for @marsaud/smb2
 */

declare module '@marsaud/smb2' {
  interface SMB2Options {
    share: string;
    domain: string;
    username: string;
    password: string;
    autoCloseTimeout?: number;
  }

  interface ReadFileOptions {
    encoding?: BufferEncoding;
  }

  class SMB2 {
    constructor(options: SMB2Options);

    readFile(
      path: string,
      options: ReadFileOptions,
      callback: (err: Error | null, data: string | Buffer) => void
    ): void;

    readFile(
      path: string,
      callback: (err: Error | null, data: Buffer) => void
    ): void;

    writeFile(
      path: string,
      data: string | Buffer,
      callback: (err: Error | null) => void
    ): void;

    readdir(
      path: string,
      callback: (err: Error | null, files: string[]) => void
    ): void;

    exists(
      path: string,
      callback: (err: Error | null, exists: boolean) => void
    ): void;

    unlink(
      path: string,
      callback: (err: Error | null) => void
    ): void;

    rename(
      oldPath: string,
      newPath: string,
      callback: (err: Error | null) => void
    ): void;

    mkdir(
      path: string,
      callback: (err: Error | null) => void
    ): void;

    rmdir(
      path: string,
      callback: (err: Error | null) => void
    ): void;

    close(callback?: (err: Error | null) => void): void;
  }

  export = SMB2;
}
