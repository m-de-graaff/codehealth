import { readFile } from "fs";

export function add(left: number, right: number): number {
  return left + right;
}

export function identity<T>(value: T): T {
  return value;
}

export const mapValue = <T>(value: T): T => value;

async function fetchValue(): Promise<number> {
  return 1;
}

class Worker {
  run(input: string): string {
    return input.trim();
  }
}

function outer(): number {
  function inner(): number {
    return 1;
  }

  return inner();
}

readFile;
